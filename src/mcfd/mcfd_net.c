#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <assert.h>

#include "mcfd_common.h"
#include "mcfd_net.h"

#include "crypto_helpers.h"

#define DGRAM_DATA_SIZE (((MCFD_BLOCK_SIZE / 8) * 8) - sizeof(unsigned short))
static_assert(DGRAM_DATA_SIZE <= SSIZE_MAX, "DGRAM_DATA_SIZE too large");
static_assert(DGRAM_DATA_SIZE < USHRT_MAX, "DGRAM_DATA_SIZE too large");

struct dgram_t {
	unsigned short size;
	unsigned char data[DGRAM_DATA_SIZE];
} __attribute__((packed));

static struct dgram_t dgram;

#define CRYPT_SIZE (sizeof(dgram) + MCFD_TAG_BYTES)

#define BUF_SIZE (MCFD_NET_CRYPT_BUF_SIZE + MCFD_TAG_BYTES)
static_assert(BUF_SIZE >= CRYPT_SIZE, "BUF_SIZE too small");
static_assert(BUF_SIZE <= SSIZE_MAX, "BUF_SIZE too large");

static unsigned char buf[BUF_SIZE];

void clear_buffers(void)
{
	explicit_bzero(buf, BUF_SIZE);
	explicit_bzero(&dgram, sizeof(dgram));
}

int net_send(int sock, const unsigned char *outbuf, const size_t outbuf_size)
{
	assert(sock != -1);
	assert(outbuf != NULL);

	if (outbuf_size > SSIZE_MAX || outbuf_size == 0) {
		return -1;
	}

	size_t bytes_to_send = outbuf_size;
	const unsigned char *cur_buf = outbuf;
	ssize_t slen = 0;
	while (bytes_to_send > 0) {
		slen = send(sock, cur_buf, bytes_to_send, MSG_NOSIGNAL);

		/* Error */
		if (slen < 0) {
			if (errno != EINTR) {
				print_err("send", strerror(errno));
				return -1;
			}

			continue;
		}

		/* Connection closed */
		if (slen == 0) {
			print_err("send", "no data sent");
			return -1;
		}

		assert(bytes_to_send <= SSIZE_MAX);
		assert(slen <= (ssize_t) bytes_to_send);

		bytes_to_send -= slen;
		cur_buf += slen;
	}

	assert(bytes_to_send == 0);
	assert(cur_buf == outbuf + outbuf_size);

	return 0;
}

int net_recv(int sock, unsigned char *inbuf, const size_t inbuf_size)
{
	assert(sock != -1);
	assert(inbuf != NULL);

	if (inbuf_size > SSIZE_MAX || inbuf_size == 0) {
		return -1;
	}

	size_t bytes_to_recv = inbuf_size;
	unsigned char *cur_buf = inbuf;
	ssize_t rlen = 0;
	while (bytes_to_recv > 0) {
		rlen = recv(sock, cur_buf, bytes_to_recv, MSG_WAITALL);

		/* Error */
		if (rlen < 0) {
			if (errno != EINTR) {
				print_err("receive", strerror(errno));
				return -1;
			}

			continue;
		}

		/* Connection closed */
		if (rlen == 0) {
			return 1;
		}

		assert(bytes_to_recv <= SSIZE_MAX);
		assert(rlen <= (ssize_t) bytes_to_recv);

		bytes_to_recv -= rlen;
		cur_buf += rlen;
	}

	assert(bytes_to_recv == 0);
	assert(cur_buf == inbuf + inbuf_size);

	return 0;
}

/* No cleanup here, caller has to take care of that. */
static int _send_crypt(int crypt_sock, mcfd_cipher *c_enc, const unsigned char *outbuf,
		const size_t outbuf_size)
{
	assert(crypt_sock != -1);
	assert(c_enc != NULL);
	assert(outbuf != NULL);

	if (outbuf_size > (size_t) (BUF_SIZE - MCFD_TAG_BYTES)) {
		print_err("send crypt", "too much data");
		return -1;
	}

	assert(outbuf_size + MCFD_TAG_BYTES <= CRYPT_SIZE);

	if (mcfd_cipher_encrypt(c_enc, outbuf, outbuf_size, buf,
				buf + outbuf_size) != 0) {
		print_err("encrypt", "encryption failed");
		return -1;
	}

	return net_send(crypt_sock, buf, outbuf_size + MCFD_TAG_BYTES);
}

int send_crypt(int crypt_sock, mcfd_cipher *c_enc, const unsigned char *outbuf,
		const size_t outbuf_size)
{
	int ret = _send_crypt(crypt_sock, c_enc, outbuf, outbuf_size);

	/* Do a cleanup just in case. */
	clear_buffers();

	return ret;
}

/* No cleanup here, caller has to take care of that. */
static int _recv_crypt(int crypt_sock, mcfd_cipher *c_dec, unsigned char *inbuf,
		const size_t inbuf_size)
{
	assert(crypt_sock != -1);
	assert(c_dec != NULL);
	assert(inbuf != NULL);

	if (inbuf_size > (size_t) (BUF_SIZE - MCFD_TAG_BYTES)) {
		print_err("recv crypt", "too much data");
		return -1;
	}

	assert(inbuf_size + MCFD_TAG_BYTES <= CRYPT_SIZE);

	int ret = net_recv(crypt_sock, buf, inbuf_size + MCFD_TAG_BYTES);
	if (ret != 0) {
		return ret;
	}

	if (mcfd_cipher_decrypt(c_dec, buf, inbuf_size, buf + inbuf_size, inbuf) != 0) {
		print_err("decrypt", "decryption failed");
		return -1;
	}

	return 0;
}

int recv_crypt(int crypt_sock, mcfd_cipher *c_dec, unsigned char *inbuf,
		const size_t inbuf_size)
{
	int ret = _recv_crypt(crypt_sock, c_dec, inbuf, inbuf_size);

	/* Do a cleanup just in case. */
	clear_buffers();

	return ret;

}

int crypt_to_plain(int crypt_sock, int plain_sock, mcfd_cipher *c_dec)
{
	assert(crypt_sock != -1);
	assert(plain_sock != -1);
	assert(c_dec != NULL);

	int ret = _recv_crypt(crypt_sock, c_dec, (unsigned char *) &dgram, sizeof(dgram));
	if (ret != 0) {
		goto out;
	}

	ret = -1;

	dgram.size = ntohs(dgram.size);
	if (dgram.size > (unsigned short) DGRAM_DATA_SIZE) {
		print_err("send plain", "invalid length");
		goto out;
	}

	assert(dgram.size <= (unsigned short) DGRAM_DATA_SIZE);

	ret = net_send(plain_sock, dgram.data, dgram.size);

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

	/* Clear the buffer to make sure we don't accidentally send old data. */
	memset(&dgram, 0, sizeof(dgram));

	ssize_t rlen = -1;
	for (;;) {
		rlen = recv(plain_sock, dgram.data, DGRAM_DATA_SIZE, 0);

		if (rlen > 0) {
			break;
		}

		/* Connection closed */
		if (rlen == 0) {
			ret = 1;
			goto out;
		}

		/* Error */
		if (errno != EINTR) {
			print_err("receive", strerror(errno));
			goto out;
		}
	}

	assert((rlen <= (ssize_t) DGRAM_DATA_SIZE) & (rlen > 0));

	dgram.size = htons(rlen);

	ret = _send_crypt(crypt_sock, c_enc, (unsigned char *) &dgram, sizeof(dgram));

out:
	/* Do a cleanup just in case. */
	clear_buffers();

	return ret;
}

static int get_addr_family(enum op_addr_family family)
{
	int ret = 0;

	switch (family) {
	case ADDR_FAMILY_ANY:
		ret = AF_UNSPEC;
		break;
	case ADDR_FAMILY_4:
		ret = AF_INET;
		break;
	case ADDR_FAMILY_6:
		ret = AF_INET6;
		break;
	default:
		assert(0);
	}

	return ret;
}

static struct addrinfo *_net_resolve(const char *addr, const char *port, int family,
		int flags)
{
	assert(port != NULL);

	struct addrinfo hints; /* What kind of socket do we want? */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = flags | AI_ADDRCONFIG;
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

		return NULL;
	}

	return result;
}

struct addrinfo *net_resolve(const char *addr, const char *port, enum op_addr_family family)
{
	assert(port != NULL);

	return _net_resolve(addr, port, get_addr_family(family), 0);
}

void net_resolve_free(struct addrinfo *gai_result)
{
	assert(gai_result != NULL);

	freeaddrinfo(gai_result);
}

int net_connect(struct addrinfo *gai_result)
{
	assert(gai_result != NULL);

	int sock = -1;

	struct addrinfo *rp = NULL;
	for (rp = gai_result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1) {
			print_err("socket", strerror(errno));
			continue;
		}

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			assert(sock != -1);
			return sock;
		}

		print_err("connect", strerror(errno));

		close(sock);
		sock = -1;
	}

	print_err("net_connect", "Could not connect");
	assert(sock == -1);

	return -1;
}

int create_listen_socket(const char *addr, const char *port, enum op_addr_family family)
{
	assert(port != NULL);

	int sock = -1;

	struct addrinfo *res_result = _net_resolve(addr, port, get_addr_family(family),
			AI_PASSIVE);
	if (res_result == NULL) {
		return -1;
	}

	struct addrinfo *rp = NULL;
	for (rp = res_result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1) {
			print_err("socket", strerror(errno));
			continue;
		}

		int reuse = 1; /* TIME_WAIT assassination */
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
					sizeof(reuse)) != 0) {
			print_err("setsockopt", strerror(errno));
			/* We really don't care if this was successful or not,
			 * so we continue. */
		}

		if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			if (listen(sock, 0) == 0) {
				freeaddrinfo(res_result);
				assert(sock != -1);
				return sock;
			}

			print_err("listen", strerror(errno));
		} else {
			print_err("bind", strerror(errno));
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(res_result);

	print_err("create_listen_socket", "Could not bind");
	assert(sock == -1);

	return -1;
}
