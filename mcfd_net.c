#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <assert.h>

#include "mcfd_common.h"
#include "mcfd_net.h"

#define DGRAM_DATA_SIZE ((MCFD_BLOCK_SIZE / 8) * 4)

struct dgram_t {
	unsigned short size;
	unsigned char data[DGRAM_DATA_SIZE];
} __attribute__((packed));

#define CRYPT_SIZE (sizeof(struct dgram_t))
#define TAG_SIZE (MCFD_TAG_BITS / 8)
#define BUF_SIZE (CRYPT_SIZE + TAG_SIZE)

static struct dgram_t dgram;
static unsigned char buf[BUF_SIZE];

void clear_buffers(void)
{
	memset(buf, 0, BUF_SIZE);
	memset(&dgram, 0, CRYPT_SIZE);
}

int crypt_to_plain(int crypt_sock, int plain_sock, mcfd_cipher *c_dec)
{
	assert(crypt_sock != -1);
	assert(plain_sock != -1);
	assert(c_dec != NULL);

	int ret = -1;

	/* TODO: determine if we have to consider signals here */
	int rlen = recv(crypt_sock, buf, BUF_SIZE, MSG_WAITALL);

	/* Error */
	if (rlen < 0) {
		print_err("receive crypt", strerror(errno));
		goto out;
	}

	/* Connection closed */
	if (rlen == 0) {
		ret = 1;
		goto out;
	}

	if (rlen != BUF_SIZE) {
		print_err("receive crypt", "data not received");
		goto out;
	}

	if (mcfd_cipher_decrypt(c_dec, buf, CRYPT_SIZE, buf + CRYPT_SIZE,
				(unsigned char *) &dgram) != 0) {
		print_err("decrypt", "decryption failed");
		goto out;
	}

	dgram.size = ntohs(dgram.size);
	if (dgram.size > (unsigned short) DGRAM_DATA_SIZE) {
		print_err("send plain", "invalid length");
		goto out;
	}

	assert(dgram.size <= DGRAM_DATA_SIZE);

	/* TODO: determine if we have to consider signals here */
	int slen = send(plain_sock, dgram.data, dgram.size, MSG_NOSIGNAL);

	/* Error */
	if (slen < 0) {
		print_err("send plain", strerror(errno));
		goto out;
	}

	/* Connection closed */
	if (slen != dgram.size) {
		print_err("send plain", "data not sent");
		goto out;
	}

	ret = 0;

out:
	/* Do a cleanup just in case. */
	clear_buffers();

	return ret;
}

int plain_to_crypt(int plain_sock, int crypt_sock, mcfd_cipher *c_enc)
{
	assert(plain_sock != -1);
	assert(crypt_sock != -1);
	assert(c_enc != NULL);

	int ret = -1;

	/* TODO: determine if we have to consider signals here */
	int rlen = recv(plain_sock, dgram.data, DGRAM_DATA_SIZE, 0);

	/* Error */
	if (rlen < 0) {
		print_err("receive plain", strerror(errno));
		goto out;
	}

	/* Connection closed */
	if (rlen == 0) {
		ret = 1;
		goto out;
	}

	assert(rlen <= DGRAM_DATA_SIZE);

	dgram.size = htons(rlen);

	if (mcfd_cipher_encrypt(c_enc, (unsigned char *) &dgram, CRYPT_SIZE, buf,
				buf + CRYPT_SIZE) != 0) {
		print_err("encrypt", "encryption failed");
		goto out;
	}

	/* TODO: determine if we have to consider signals here */
	int slen = send(crypt_sock, buf, BUF_SIZE, MSG_NOSIGNAL);

	/* Error */
	if (slen < 0) {
		print_err("send crypt", strerror(errno));
		goto out;
	}

	/* Connection closed */
	if (slen != BUF_SIZE) {
		print_err("send crypt", "data not sent");
		goto out;
	}

	ret = 0;

out:
	/* Do a cleanup just in case. */
	clear_buffers();

	return ret;
}

int connect_to_server(int *sock, const char *addr, const char *port)
{
	assert(sock != NULL);
	assert(port != NULL);

	*sock = -1;

	struct addrinfo hints; /* Where do we want to connect to? */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_TCP;

	/* The result of getaddrinfo. Do not modify this, we need to free it later. */
	struct addrinfo *result = NULL;

	int err = getaddrinfo(addr, port, &hints, &result);
	if (err != 0) {
		/* Can getaddrinfo fail, while still allocating space? */
		if (result != NULL) {
			freeaddrinfo(result);
		}

		print_err("getaddrinfo", gai_strerror(err));

		return -1;
	}

	struct addrinfo *rp = NULL;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (*sock == -1) {
			continue;
		}

		if (connect(*sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			freeaddrinfo(result);
			assert(*sock != -1);
			return *sock;
		}

		close(*sock);
		*sock = -1;
	}

	/* Free the result-list of getaddrinfo */
	freeaddrinfo(result);

	print_err("connect_to_server", "Could not connect");
	assert(*sock == -1);

	return -1;
}

int create_listen_socket(int *sock, const char *addr, const char *port)
{
	assert(sock != NULL);
	assert(port != NULL);

	*sock = -1;

	struct addrinfo hints; /* What kind of socket do we want? */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* The result of getaddrinfo. Do not modify this, we need to free it later. */
	struct addrinfo *result = NULL;

	int err = getaddrinfo(addr, port, &hints, &result);
	if (err != 0) {
		/* Can getaddrinfo fail, while still allocating space? */
		if (result != NULL) {
			freeaddrinfo(result);
		}

		print_err("getaddrinfo", gai_strerror(err));

		return -1;
	}

	struct addrinfo *rp = NULL;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (*sock == -1) {
			continue;
		}

		int reuse = 1; /* TIME_WAIT assassination */
		if (setsockopt (*sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
					sizeof(reuse)) != 0) {
			print_err("setsockopt", strerror(errno));
			/* We really don't care if this was successful or not,
			 * so we continue. */
		}

		if (bind(*sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			if (listen(*sock, 0) == 0) {
				freeaddrinfo(result);
				assert(*sock != -1);
				return *sock;
			}
		}

		close(*sock);
		*sock = -1;
	}

	/* Free the result-list of getaddrinfo */
	freeaddrinfo(result);

	print_err("create_listen_socket", "Could not bind");
	assert(*sock == -1);

	return -1;
}
