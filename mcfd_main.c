#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_auth.h"
#include "mcfd_common.h"
#include "mcfd_crypto.h"
#include "mcfd_net.h"

static mcfd_cipher *c_enc = NULL;
static mcfd_cipher *c_dec = NULL;

const char *progname = "mcfd";

static int listen_sock = -1;

static int client_sock = -1;
static int server_sock = -1;

static unsigned char key[MCFD_KEY_BYTES];
static unsigned char nonce_enc[MCFD_NONCE_BYTES];
static unsigned char nonce_dec[MCFD_NONCE_BYTES];

void cleanup(void)
{
	explicit_bzero(key, MCFD_KEY_BYTES);
	explicit_bzero(nonce_enc, MCFD_NONCE_BYTES);
	explicit_bzero(nonce_dec, MCFD_NONCE_BYTES);

	if (c_enc != NULL) {
		mcfd_cipher_free(c_enc);
		c_enc = NULL;
	}

	if (c_dec != NULL) {
		mcfd_cipher_free(c_dec);
		c_dec = NULL;
	}

	clear_buffers();

	if (listen_sock != -1) {
		close(listen_sock);
		listen_sock = -1;
	}

	if (client_sock != -1) {
		close(client_sock);
		client_sock = -1;
	}

	if (server_sock != -1) {
		close(server_sock);
		server_sock = -1;
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [-f] [-s] [-l <listen_addr>] -k <key> <listen_port> "
			"<dst_addr> <dst_port>\n", progname);
	terminate(EXIT_FAILURE);
}

enum op_mode {
	MODE_CLIENT = 0,
	MODE_SERVER
};

static void handle_connection(const char *dst_addr, const char *dst_port,
		const enum op_mode mode)
{
	assert(client_sock != -1);
	assert(c_enc != NULL);
	assert(c_dec != NULL);

	close(listen_sock);
	listen_sock = -1;

	/* TODO: investigate SRP. */

	int crypt_sock = -1;
	int plain_sock = -1;
	if (mode == MODE_CLIENT) {
		assert(server_sock == -1);

		server_sock = connect_to_server(&server_sock, dst_addr, dst_port);
		if (server_sock == -1) {
			terminate(EXIT_FAILURE);
		}
		crypt_sock = server_sock;

		if (mcfd_auth_client(crypt_sock, c_enc, c_dec, key, nonce_enc,
					nonce_dec) != 0) {
			print_err("auth", "failed to authenticate server");
			terminate(EXIT_FAILURE);
		}

	} else {
		crypt_sock = client_sock;

		if (mcfd_auth_server(crypt_sock, c_enc, c_dec, key, nonce_enc,
					nonce_dec) != 0) {
			print_err("auth", "failed to authenticate client");
			terminate(EXIT_FAILURE);
		}

	}

	/* We disable signals here to absolutely make sure that the old ciphers are
	 * properly destroyed. */
	block_signals();

	mcfd_cipher_free(c_enc);
	mcfd_cipher_free(c_dec);

	c_enc = mcfd_cipher_init(nonce_enc, key);
	c_dec = mcfd_cipher_init(nonce_dec, key);

	unblock_signals();

	explicit_bzero(key, MCFD_KEY_BYTES);
	explicit_bzero(nonce_enc, MCFD_NONCE_BYTES);
	explicit_bzero(nonce_dec, MCFD_NONCE_BYTES);

	if (mode == MODE_CLIENT) {
		plain_sock = client_sock;
	} else {
		assert(server_sock == -1);

		server_sock = connect_to_server(&server_sock, dst_addr, dst_port);
		if (server_sock == -1) {
			terminate(EXIT_FAILURE);
		}
		plain_sock = server_sock;
	}

	assert(crypt_sock != -1);
	assert(plain_sock != -1);

	struct pollfd fds[2];
	fds[0].fd = server_sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	fds[1].fd = client_sock;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	for (;;) {
		/* TODO: determine if we have to consider signals here */
		int err = poll(fds, 2, -1);
		if (err < 0) {
			print_err("poll", strerror(errno));
			terminate(EXIT_FAILURE);
		}

		assert(err != 0);

		struct pollfd *pfd;
		for (pfd = fds; pfd < fds + 2; pfd++) {
			/* Nothing at this fd */
			if (pfd->revents == 0) {
				continue;
			}

			/* Connection closed */
			if (pfd->revents & (POLLHUP)) {
				terminate(EXIT_SUCCESS);
			}

			/* Some error, terminate */
			if (pfd->revents & (POLLERR | POLLNVAL)) {
				print_err("handle_connection", "socket error");
				terminate(EXIT_FAILURE);
			}

			assert(pfd->revents & POLLIN);

			int err;
			if (pfd->fd == crypt_sock) {
				err = crypt_to_plain(crypt_sock, plain_sock, c_dec);
			} else if (pfd->fd == plain_sock) {
				err = plain_to_crypt(plain_sock, crypt_sock, c_enc);
			} else {
				assert(0);
			}

			/* Error */
			if (err < 0) {
				terminate(EXIT_FAILURE);
			/* Connection closed */
			} else if (err > 0) {
				terminate(EXIT_SUCCESS);
			}
		}
	}

	assert(0);
}

/* TODO: investigate timing impact of asserts */
/* TODO: speed up transmission (a lot) */
/* TODO: add more meaningful output */
int main(int argc, char *const *argv)
{
	if (argc < 6 || argc > 10) {
		usage();
	}

	/* we need a program name */
	if (argv[0] == NULL) {
		print_err("set name", "No program name given.");
		terminate(EXIT_FAILURE);
	}

	progname = argv[0];

	char *listen_addr = NULL;

	/* Argument parsing */
	int do_fork = 0;
	char *pass;
	size_t pass_len;
	enum op_mode mode = MODE_CLIENT;
	int opt;
	while ((opt = getopt(argc, argv, "fk:l:s")) != EOF) {
		switch (opt) {
		case 'f':
			do_fork = 1;

			break;
		case 'k':
			if (optarg == NULL) {
				usage();
			}

			pass_len = strlen(optarg);
			if (pass_len == 0) {
				usage();
			}

			pass = optarg;

			break;
		case 'l':
			if (optarg == NULL) {
				usage();
			}

			listen_addr = optarg;
			break;
		case 's':
			mode = MODE_SERVER;
			break;
		case '?':
			usage();
		default:
			/* never happens, ever */
			assert(0);
		}
	}

	if (optind != argc - 3) {
		usage();
	}

	assert(optind == argc - 3);

	if (argv[optind] == NULL || argv[optind + 1] == NULL
			|| argv[optind + 2] == NULL) {
		usage();
	}

	char *listen_port = argv[optind];
	char *dst_addr = argv[optind + 1];
	char *dst_port = argv[optind + 2];

	setup_signal_handlers();

	/* TODO: Is this really necessary? */
	/* Disable signals here to make sure the key is correctly destroyed again. */
	block_signals();

	/* TODO: figure out how to deal with the salt */
	if (mcfd_kdf(pass, pass_len, NULL, 0, key) != 0) {
		print_err("init ciphers", "failed to derive key");
		terminate(EXIT_FAILURE);
	}

	explicit_bzero(pass, pass_len);

	/* Reverse keys in one direction to simplify auth. */
	if (mode == MODE_CLIENT) {
		c_enc = mcfd_cipher_init(NULL, key);
		reverse_bytes(key, MCFD_KEY_BYTES);
		c_dec = mcfd_cipher_init(NULL, key);
	} else {
		c_dec = mcfd_cipher_init(NULL, key);
		reverse_bytes(key, MCFD_KEY_BYTES);
		c_enc = mcfd_cipher_init(NULL, key);
	}

	explicit_bzero(key, MCFD_KEY_BYTES);

	unblock_signals();

	if (c_enc == NULL || c_dec == NULL) {
		print_err("init ciphers", "failed to init ciphers");
		terminate(EXIT_FAILURE);
	}

	listen_sock = create_listen_socket(&listen_sock, listen_addr, listen_port);
	if (listen_sock == -1) {
		terminate(EXIT_FAILURE);
	}

	for(;;) {
		assert(client_sock == -1);

		client_sock = accept(listen_sock, NULL, NULL);
		if (client_sock < 0) {
			if (errno != EINTR) {
				print_err("accept", strerror(errno));
			}

			client_sock = -1;
			continue;
		}

		pid_t pid = 0;

		if (do_fork) {
			pid = fork();
		}

		if (pid == 0) {
			/* child */
			handle_connection(dst_addr, dst_port, mode);
			assert(0);
		} else if (pid < 0) {
			print_err("fork", strerror(errno));
		}

		close(client_sock);
		client_sock = -1;
	}

	assert(0);

	return EXIT_FAILURE;
}
