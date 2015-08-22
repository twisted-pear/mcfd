#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <assert.h>

#include <mcfd_config.h>

#include "crypto_helpers.h"
#include "mcfd_auth.h"
#include "mcfd_common.h"
#include "mcfd_cipher.h"
#include "mcfd_kdf.h"
#include "mcfd_net.h"
#include "mcfd_random.h"

#ifdef USE_SECCOMP
#	include "mcfd_seccomp.h"
#endif /* USE_SECCOMP */

static mcfd_cipher *c_auth = NULL;
static mcfd_cipher *c_enc = NULL;
static mcfd_cipher *c_dec = NULL;

const char *progname = "mcfd";

static int listen_sock = -1;
static int listen_sock2 = -1;

static int client_sock = -1;
static int server_sock = -1;

static unsigned char key_auth[MCFD_KEY_BYTES];
static unsigned char key_enc[MCFD_KEY_BYTES];
static unsigned char key_dec[MCFD_KEY_BYTES];

static unsigned char nonce_auth[MCFD_NONCE_BYTES];
static unsigned char nonce_enc[MCFD_NONCE_BYTES];
static unsigned char nonce_dec[MCFD_NONCE_BYTES];

static struct termios *term_old = NULL;

void cleanup(void)
{
	explicit_bzero(key_auth, MCFD_KEY_BYTES);
	explicit_bzero(key_enc, MCFD_KEY_BYTES);
	explicit_bzero(key_dec, MCFD_KEY_BYTES);

	explicit_bzero(nonce_auth, MCFD_NONCE_BYTES);
	explicit_bzero(nonce_enc, MCFD_NONCE_BYTES);
	explicit_bzero(nonce_dec, MCFD_NONCE_BYTES);

	if (c_auth != NULL) {
		mcfd_cipher_free(c_auth);
		c_auth = NULL;
	}

	if (c_enc != NULL) {
		mcfd_cipher_free(c_enc);
		c_enc = NULL;
	}

	if (c_dec != NULL) {
		mcfd_cipher_free(c_dec);
		c_dec = NULL;
	}

	mcfd_random_destroy();

	clear_buffers();

	if (term_old != NULL) {
		(void) tcsetattr(STDIN_FILENO, TCSANOW, term_old);
	}

	if (listen_sock != -1) {
		close(listen_sock);
		listen_sock = -1;
	}

	if (listen_sock2 != -1) {
		close(listen_sock2);
		listen_sock2 = -1;
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

noreturn static void usage(void)
{
	fprintf(stderr, "Usage: %s [-f|-r] [-s] [-4|-6] [-v[v[v]]] [-l <listen_addr>] [-k <key>] "
			"<listen_port> <dst_addr> <dst_port>\n", progname);
	terminate(EXIT_FAILURE);
}

enum op_mode {
	MODE_CLIENT = 0,
	MODE_SERVER
};

enum op_dir {
	DIR_NORMAL = 0,
	DIR_REVERSED
};

static_assert(MCFD_RANDOM_MAX >= (MCFD_AUTH_RANDOM_BYTES + MCFD_NONCE_BYTES),
		"MCFD_RANDOM_MAX too small");

#define AUTH_BUF_SIZE MCFD_AUTH_PHASE2_SERVER_IN_BYTES
static unsigned char auth_buf[AUTH_BUF_SIZE];
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_RANDOM_BYTES, "AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE1_SERVER_OUT_BYTES,
		"AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE2_SERVER_IN_BYTES,
		"AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE2_SERVER_OUT_BYTES,
		"AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE1_CLIENT_IN_BYTES,
		"AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES,
		"AUTH_BUF_SIZE too small");
static_assert(AUTH_BUF_SIZE >= MCFD_AUTH_PHASE2_CLIENT_IN_BYTES,
		"AUTH_BUF_SIZE too small");

static int authenticate_client(mcfd_auth_context *ctx, int crypt_sock,
		mcfd_cipher *c_auth, unsigned char *key_enc, unsigned char *key_dec,
		unsigned char *nonce_enc, unsigned char *nonce_dec)
{
	assert(ctx != NULL);

	/* auth phase 1 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_CLIENT_IN_BYTES) != 0) {
		return 1;
	}
	if (mcfd_auth_phase1_client(ctx, c_auth, auth_buf, auth_buf) != 0) {
		return 1;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES) != 0) {
		return 1;
	}

	/* auth phase 2 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_CLIENT_IN_BYTES) != 0) {
		return 1;
	}
	if (mcfd_auth_phase2_client(ctx, c_auth, auth_buf) != 0) {
		return 1;
	}

	/* Get new keys and nonces. */
	if (mcfd_auth_finish(ctx, key_dec, key_enc, nonce_dec, nonce_enc) != 0) {
		return 1;
	}

	return 0;
}

static int authenticate_server(mcfd_auth_context *ctx, int crypt_sock,
		mcfd_cipher *c_auth, unsigned char *key_enc, unsigned char *key_dec,
		unsigned char *nonce_enc, unsigned char *nonce_dec)
{
	assert(ctx != NULL);

	/* auth phase 1 */
	if (mcfd_auth_phase1_server(ctx, auth_buf) != 0) {
		return 1;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_SERVER_OUT_BYTES)
			!= 0) {
		return 1;
	}

	/* auth phase 2 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_SERVER_IN_BYTES) != 0) {
		return 1;
	}
	if (mcfd_auth_phase2_server(ctx, c_auth, auth_buf, auth_buf) != 0) {
		return 1;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_SERVER_OUT_BYTES)
			!= 0) {
		return 1;
	}

	/* Get new keys and nonces. */
	if (mcfd_auth_finish(ctx, key_enc, key_dec, nonce_enc, nonce_dec) != 0) {
		return 1;
	}

	return 0;
}

static int authenticate(int crypt_sock, const enum op_mode mode, mcfd_cipher *c_auth,
		unsigned char *key_enc, unsigned char *key_dec, unsigned char *nonce_enc,
		unsigned char *nonce_dec)
{
	assert(crypt_sock != -1);
	assert(c_auth != NULL);
	assert(key_enc != NULL);
	assert(key_dec != NULL);
	assert(nonce_enc != NULL);
	assert(nonce_dec != NULL);

	if (mcfd_random_get(auth_buf, MCFD_AUTH_RANDOM_BYTES) != 0) {
		return 1;
	}

	mcfd_auth_context *ctx = mcfd_auth_init(auth_buf);
	if (ctx == NULL) {
		explicit_bzero(auth_buf, AUTH_BUF_SIZE);
		return 1;
	}

	int ret = 0;
	if (mode == MODE_CLIENT) {
		ret = authenticate_client(ctx, crypt_sock, c_auth, key_enc, key_dec,
				nonce_enc, nonce_dec);
	} else {
		ret = authenticate_server(ctx, crypt_sock, c_auth, key_enc, key_dec,
				nonce_enc, nonce_dec);
	}

	explicit_bzero(auth_buf, AUTH_BUF_SIZE);
	mcfd_auth_free(ctx);

	return ret;
}

static int forward(int plain_sock, int crypt_sock, mcfd_cipher *c_enc, mcfd_cipher *c_dec)
{
	assert(crypt_sock != -1);
	assert(plain_sock != -1);

	assert(c_enc != NULL);
	assert(c_dec != NULL);

	struct pollfd fds[2];
	fds[0].fd = server_sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	fds[1].fd = client_sock;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	for (;;) {
		int err = -1;
		for (;;) {
			err = poll(fds, 2, -1);

			if (err > 0) {
				break;
			}

			assert(err < 0);

			if (errno != EINTR) {
				print_err("poll", strerror(errno));
				return 1;
			}
		}

		assert(err > 0);

		struct pollfd *pfd;
		for (pfd = fds; pfd < fds + 2; pfd++) {
			/* Nothing at this fd */
			if (pfd->revents == 0) {
				continue;
			}

			/* Connection closed */
			if (pfd->revents & (POLLHUP)) {
				return 0;
			}

			/* Some error, terminate */
			if (pfd->revents & (POLLERR | POLLNVAL)) {
				print_err("handle_connection", "socket error");
				return 1;
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
				return 1;
			/* Connection closed */
			} else if (err > 0) {
				return 0;
			}
		}
	}

	assert(0);
}

static int get_auth_nonce(const enum op_mode mode, int crypt_sock, unsigned char *nonce)
{
	assert(crypt_sock != -1);
	assert(nonce != NULL);

	if (mode == MODE_CLIENT) {
		if (mcfd_random_get(nonce, MCFD_NONCE_BYTES) != 0) {
			print_err("gen nonce", "failed to generate auth nonce");
			return 1;
		}
		if (net_send(crypt_sock, nonce, MCFD_NONCE_BYTES) != 0) {
			print_err("send nonce", "failed to send auth nonce");
			return 1;
		}
	} else {
		if (net_recv(crypt_sock, nonce, MCFD_NONCE_BYTES) != 0) {
			print_err("recv nonce", "failed to receive auth nonce");
			return 1;
		}
	}

	return 0;
}

static mcfd_cipher *get_cipher(unsigned char *nonce, unsigned char *key)
{
	assert(nonce != NULL);
	assert(key != NULL);

	mcfd_cipher *c = mcfd_cipher_init(nonce, key);

	explicit_bzero(key, MCFD_KEY_BYTES);
	explicit_bzero(nonce, MCFD_KEY_BYTES);

	return c;
}

noreturn static void handle_connection_server(const char *dst_addr, const char *dst_port,
		const enum op_addr_family family)
{
	assert(client_sock != -1);
	assert(c_auth == NULL);
	assert(c_enc == NULL);
	assert(c_dec == NULL);

	int crypt_sock = -1;
	int plain_sock = -1;

	struct addrinfo *res_result = net_resolve(dst_addr, dst_port, family);
	if (res_result == NULL) {
		terminate(EXIT_FAILURE);
	}

	crypt_sock = client_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_preauth_server() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	if (get_auth_nonce(MODE_SERVER, crypt_sock, nonce_auth) != 0) {
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	block_signals();

	c_auth = get_cipher(nonce_auth, key_auth);

	unblock_signals();

	if (c_auth == NULL) {
		print_err("init cipher", "failed to init auth cipher");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	if (authenticate(crypt_sock, MODE_SERVER, c_auth, key_enc, key_dec, nonce_enc,
				nonce_dec) != 0) {
		print_err("auth", "failed to authenticate");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	/* We disable signals here to absolutely make sure that the old ciphers are
	 * properly destroyed. */
	block_signals();

	mcfd_cipher_free(c_auth);
	c_auth = NULL;

	c_enc = get_cipher(nonce_enc, key_enc);
	c_dec = get_cipher(nonce_dec, key_dec);

	unblock_signals();

	if (c_enc == NULL || c_dec == NULL) {
		print_err("init ciphers", "failed to init encryption ciphers");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	assert(server_sock == -1);

	server_sock = net_connect(res_result);
	net_resolve_free(res_result);

	if (server_sock == -1) {
		terminate(EXIT_FAILURE);
	}
	plain_sock = server_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_postauth() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	assert(c_auth == NULL);

	if (forward(plain_sock, crypt_sock, c_enc, c_dec) != 0) {
		terminate(EXIT_FAILURE);
	}

	terminate(EXIT_SUCCESS);

	assert(0);
}

noreturn static void handle_connection_client(const char *dst_addr, const char *dst_port,
		const enum op_addr_family family)
{
	assert(client_sock != -1);
	assert(c_auth == NULL);
	assert(c_enc == NULL);
	assert(c_dec == NULL);

	int crypt_sock = -1;
	int plain_sock = -1;

	struct addrinfo *res_result = net_resolve(dst_addr, dst_port, family);
	if (res_result == NULL) {
		terminate(EXIT_FAILURE);
	}

	assert(server_sock == -1);

	server_sock = net_connect(res_result);
	net_resolve_free(res_result);

	if (server_sock == -1) {
		terminate(EXIT_FAILURE);
	}
	crypt_sock = server_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_preauth_client() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	if (get_auth_nonce(MODE_CLIENT, crypt_sock, nonce_auth) != 0) {
		terminate(EXIT_FAILURE);
	}

	block_signals();

	c_auth = get_cipher(nonce_auth, key_auth);

	unblock_signals();

	if (c_auth == NULL) {
		print_err("init cipher", "failed to init auth cipher");
		terminate(EXIT_FAILURE);
	}

	if (authenticate(crypt_sock, MODE_CLIENT, c_auth, key_enc, key_dec, nonce_enc, nonce_dec)
			!= 0) {
		print_err("auth", "failed to authenticate");
		terminate(EXIT_FAILURE);
	}

	/* We disable signals here to absolutely make sure that the old ciphers are
	 * properly destroyed. */
	block_signals();

	mcfd_cipher_free(c_auth);
	c_auth = NULL;

	c_enc = get_cipher(nonce_enc, key_enc);
	c_dec = get_cipher(nonce_dec, key_dec);

	unblock_signals();

	if (c_enc == NULL || c_dec == NULL) {
		print_err("init ciphers", "failed to init encryption ciphers");
		terminate(EXIT_FAILURE);
	}

	plain_sock = client_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_postauth() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	assert(c_auth == NULL);

	if (forward(plain_sock, crypt_sock, c_enc, c_dec) != 0) {
		terminate(EXIT_FAILURE);
	}

	terminate(EXIT_SUCCESS);

	assert(0);
}

noreturn static void handle_connection_sink()
{
	assert(client_sock != -1);
	assert(server_sock == -1);

	assert(c_auth == NULL);
	assert(c_enc == NULL);
	assert(c_dec == NULL);

	int crypt_sock = -1;
	int plain_sock = -1;

	crypt_sock = client_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_preauth_sink() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	if (get_auth_nonce(MODE_SERVER, crypt_sock, nonce_auth) != 0) {
		terminate(EXIT_FAILURE);
	}

	block_signals();

	c_auth = get_cipher(nonce_auth, key_auth);

	unblock_signals();

	if (c_auth == NULL) {
		print_err("init cipher", "failed to init auth cipher");
		terminate(EXIT_FAILURE);
	}

	if (authenticate(crypt_sock, MODE_SERVER, c_auth, key_enc, key_dec, nonce_enc,
				nonce_dec) != 0) {
		print_err("auth", "failed to authenticate");
		terminate(EXIT_FAILURE);
	}

	/* We disable signals here to absolutely make sure that the old ciphers are
	 * properly destroyed. */
	block_signals();

	mcfd_cipher_free(c_auth);
	c_auth = NULL;

	c_enc = get_cipher(nonce_enc, key_enc);
	c_dec = get_cipher(nonce_dec, key_dec);

	unblock_signals();

	if (c_enc == NULL || c_dec == NULL) {
		print_err("init ciphers", "failed to init encryption ciphers");
		terminate(EXIT_FAILURE);
	}

	for (;;) {
		server_sock = accept(listen_sock2, NULL, NULL);
		if (server_sock < 0) {
			if (errno != EINTR) {
				print_err("accept", strerror(errno));
			}
		} else {
			break;
		}
	}

	close(listen_sock2);
	listen_sock2 = -1;

	assert(server_sock >= 0);

	plain_sock = server_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_postauth() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	assert(c_auth == NULL);

	if (forward(plain_sock, crypt_sock, c_enc, c_dec) != 0) {
		terminate(EXIT_FAILURE);
	}

	terminate(EXIT_SUCCESS);

	assert(0);
}

noreturn static void handle_connection_source(const char *srv_addr,
		const char *srv_port, const char *dst_addr, const char *dst_port,
		const enum op_addr_family family)
{
	assert(client_sock == -1);
	assert(server_sock == -1);

	assert(c_auth == NULL);
	assert(c_enc == NULL);
	assert(c_dec == NULL);

	int crypt_sock = -1;
	int plain_sock = -1;

	struct addrinfo *res_result = net_resolve(dst_addr, dst_port, family);
	if (res_result == NULL) {
		terminate(EXIT_FAILURE);
	}

	assert(server_sock == -1);

	server_sock = net_connect(res_result);
	net_resolve_free(res_result);

	if (server_sock == -1) {
		terminate(EXIT_FAILURE);
	}
	crypt_sock = server_sock;

	res_result = net_resolve(srv_addr, srv_port, family);
	if (res_result == NULL) {
		terminate(EXIT_FAILURE);
	}

#ifdef USE_SECCOMP
	if (mcfd_seccomp_preauth_source() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	if (get_auth_nonce(MODE_CLIENT, crypt_sock, nonce_auth) != 0) {
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	block_signals();

	c_auth = get_cipher(nonce_auth, key_auth);

	unblock_signals();

	if (c_auth == NULL) {
		print_err("init cipher", "failed to init auth cipher");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	if (authenticate(crypt_sock, MODE_CLIENT, c_auth, key_enc, key_dec, nonce_enc, nonce_dec)
			!= 0) {
		print_err("auth", "failed to authenticate");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	/* We disable signals here to absolutely make sure that the old ciphers are
	 * properly destroyed. */
	block_signals();

	mcfd_cipher_free(c_auth);
	c_auth = NULL;

	c_enc = get_cipher(nonce_enc, key_enc);
	c_dec = get_cipher(nonce_dec, key_dec);

	unblock_signals();

	if (c_enc == NULL || c_dec == NULL) {
		print_err("init ciphers", "failed to init encryption ciphers");
		net_resolve_free(res_result);
		terminate(EXIT_FAILURE);
	}

	assert(client_sock == -1);

	client_sock = net_connect(res_result);
	net_resolve_free(res_result);

	if (client_sock == -1) {
		terminate(EXIT_FAILURE);
	}
	plain_sock = client_sock;

#ifdef USE_SECCOMP
	if (mcfd_seccomp_postauth() != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	assert(c_auth == NULL);

	if (forward(plain_sock, crypt_sock, c_enc, c_dec) != 0) {
		terminate(EXIT_FAILURE);
	}

	terminate(EXIT_SUCCESS);

	assert(0);
}


static char *read_password_tty(char *buf, size_t len, int fd)
{
	assert(buf != NULL);
	assert(len > 0);
	assert(isatty(fd));

	static struct termios old;
	struct termios new;

	char *ret = NULL;

	if (tcgetattr(fd, &old) != 0) {
		return NULL;
	}

	new = old;
	new.c_lflag &= ~ECHO;

	block_signals();
	term_old = &old;
	unblock_signals();

	if (tcsetattr(fd, TCSANOW, &new) != 0) {
		goto out;
	}

	printf("Enter password: ");

	ret = fgets(buf, len, stdin);

	printf("\n");

out:
	assert(term_old != NULL);

	if (tcsetattr(fd, TCSANOW, &old) != 0) {
		ret = NULL;
	}

	block_signals();
	term_old = NULL;
	unblock_signals();

	return ret;
}

#define PASS_BUF_LEN 64
static char pass_buf[PASS_BUF_LEN];

static char *read_password(void)
{
	char *ret;
	int errno_backup = errno;

	if (isatty(STDIN_FILENO)) {
		ret = read_password_tty(pass_buf, PASS_BUF_LEN, STDIN_FILENO);
	} else {
		if (errno != EINVAL && errno != ENOTTY) {
			goto err_msg;
		}

		errno = errno_backup;

		ret = fgets(pass_buf, PASS_BUF_LEN, stdin);
	}

	if (ret == NULL) {
		goto err_msg;
	}

	assert(ret == pass_buf);

	size_t pass_len = strlen(pass_buf);

	if (pass_len == 0 || pass_buf[0] == '\n') {
		print_err("read password", "no password given");
		goto err;
	}

	assert(pass_len > 0);

	/* fgets might store a newline at the end, remove it */
	if (pass_buf[pass_len - 1] == '\n') {
		assert(pass_len > 1);

		pass_buf[pass_len - 1] = '\0';
	}

	assert(ret == pass_buf);

	goto out;

err_msg:
	print_err("read password", strerror(errno));

err:
	ret = NULL;

	explicit_bzero(pass_buf, PASS_BUF_LEN);

out:
	return ret;
}

/* TODO: add more meaningful output */
int main(int argc, char *const *argv)
{
	if (argc < 4 || argc > 11) {
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
	char *pass = NULL;
	size_t pass_len = 0;
	enum op_mode mode = MODE_CLIENT;
	enum op_dir dir = DIR_NORMAL;
	enum op_addr_family family = ADDR_FAMILY_ANY;
	int verbosity = 0;
	int opt;
	while ((opt = getopt(argc, argv, "46fk:l:rsv")) != EOF) {
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
		case 'r':
			dir = DIR_REVERSED;
			break;
		case 's':
			mode = MODE_SERVER;
			break;
		case 'v':
			if (verbosity >= 3) {
				usage();
			}

			verbosity++;
			break;
		case '4':
			if (family != ADDR_FAMILY_ANY) {
				usage();
			}

			family = ADDR_FAMILY_4;
			break;
		case '6':
			if (family != ADDR_FAMILY_ANY) {
				usage();
			}

			family = ADDR_FAMILY_6;
			break;
		case '?':
			usage();
		default:
			/* never happens, ever */
			assert(0);
		}
	}

	assert(pass != NULL || pass_len == 0);

	if (optind != argc - 3) {
		usage();
	}

	assert(optind == argc - 3);

	if (argv[optind] == NULL || argv[optind + 1] == NULL
			|| argv[optind + 2] == NULL) {
		usage();
	}

	/* Don't allow reversed and fork at the same time. */
	if (dir == DIR_REVERSED && do_fork != 0) {
		usage();
	}

	assert(verbosity >= 0 && verbosity <= 3);
	set_verbosity(verbosity);

	char *listen_port = argv[optind];
	char *dst_addr = argv[optind + 1];
	char *dst_port = argv[optind + 2];

	setup_signal_handlers();

	if (pass_len == 0) {
		pass = read_password();
		if (pass == NULL) {
			terminate(EXIT_FAILURE);
		}

		pass_len = strlen(pass);
	}

	assert(pass != NULL && pass_len > 0);

#ifdef USE_SECCOMP
	if (mcfd_seccomp_preconnect(do_fork) != 0) {
		print_err("seccomp filter", "failed to install seccomp filter");
		terminate(EXIT_FAILURE);
	}
#endif /* USE_SECCOMP */

	/* TODO: Is this really necessary? */
	/* Disable signals here to make sure the key is correctly destroyed again. */
	block_signals();

	/* TODO: figure out how to deal with the salt */
	if (mcfd_kdf(pass, pass_len, NULL, 0, key_auth, MCFD_KEY_BITS) != 0) {
		print_err("init ciphers", "failed to derive key");
		terminate(EXIT_FAILURE);
	}

	explicit_bzero(pass, pass_len);

	unblock_signals();

	if (mcfd_random_init() != 0) {
		print_err("init RNG", "failed to init RNG");
		terminate(EXIT_FAILURE);
	}

	if (dir != DIR_REVERSED || mode != MODE_CLIENT) {
		listen_sock = create_listen_socket(listen_addr, listen_port, family);
		if (listen_sock == -1) {
			terminate(EXIT_FAILURE);
		}
	}

	if (dir == DIR_REVERSED && mode == MODE_SERVER) {
		listen_sock2 = create_listen_socket(dst_addr, dst_port, family);
		if (listen_sock2 == -1) {
			terminate(EXIT_FAILURE);
		}
	}

	if (dir == DIR_REVERSED && mode == MODE_CLIENT) {
		if (mcfd_random_reseed() != 0) {
			print_err("reseed RNG", "failed to reseed RNG");
			terminate(EXIT_FAILURE);
		}

		handle_connection_source(listen_addr, listen_port, dst_addr,
				dst_port, family);

		assert(0);
		return EXIT_FAILURE;
	}

	for (;;) {
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

		if (mcfd_random_reseed() != 0) {
			print_err("reseed RNG", "failed to reseed RNG");
			terminate(EXIT_FAILURE);
		}

		if (pid == 0) {
			/* child */
			close(listen_sock);
			listen_sock = -1;

			if (dir == DIR_REVERSED) {
				assert(mode == MODE_SERVER);

				handle_connection_sink();

				assert(0);
			}

			if (mode == MODE_CLIENT) {
				handle_connection_client(dst_addr, dst_port, family);
			} else {
				handle_connection_server(dst_addr, dst_port, family);
			}

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
