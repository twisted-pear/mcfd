#ifndef __MCFD_NET_H__
#define __MCFD_NET_H__

#include "mcfd_cipher.h"

void clear_buffers(void);

int net_send(int sock, const unsigned char *outbuf, const size_t outbuf_size);
int net_recv(int sock, unsigned char *inbuf, const size_t inbuf_size);

/* The maximum number of bytes send_crypt()/recv_crypt() can send/receive. */
#define MCFD_NET_CRYPT_BUF_SIZE 1016

int send_crypt(int crypt_sock, mcfd_cipher *c_enc, const unsigned char *outbuf,
		const size_t outbuf_size);
int recv_crypt(int crypt_sock, mcfd_cipher *c_dec, unsigned char *inbuf,
		const size_t inbuf_size);

int crypt_to_plain(int crypt_sock, int plain_sock, mcfd_cipher *c_dec);
int plain_to_crypt(int plain_sock, int crypt_sock, mcfd_cipher *c_enc);

enum op_addr_family {
	ADDR_FAMILY_ANY = 0,
	ADDR_FAMILY_4,
	ADDR_FAMILY_6
};

struct addrinfo *net_resolve(const char *addr, const char *port, enum op_addr_family family);
void net_resolve_free(struct addrinfo *gai_result);

int net_connect(struct addrinfo *gai_result);

int create_listen_socket(const char *addr, const char *port, enum op_addr_family family);

#endif /* __MCFD_NET_H__ */
