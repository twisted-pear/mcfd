#ifndef __MCFD_NET_H__
#define __MCFD_NET_H__

#include "mcfd_crypto.h"

void clear_buffers(void);

int net_send(int sock, const unsigned char *outbuf, const size_t outbuf_size);
int net_recv(int sock, unsigned char *inbuf, const size_t inbuf_size);

/* The maximum number of bytes send_crypt()/recv_crypt() can send/receive. */
#define MCFD_NET_CRYPT_BUF_SIZE 1024

int send_crypt(int crypt_sock, mcfd_cipher *c_enc, const unsigned char *outbuf,
		const size_t outbuf_size);
int recv_crypt(int crypt_sock, mcfd_cipher *c_dec, unsigned char *inbuf,
		const size_t inbuf_size);

int crypt_to_plain(int crypt_sock, int plain_sock, mcfd_cipher *c_dec);
int plain_to_crypt(int plain_sock, int crypt_sock, mcfd_cipher *c_enc);

int create_listen_socket(int *sock, const char *addr, const char *port);
int connect_to_server(int *sock, const char *addr, const char *port);

#endif /* __MCFD_NET_H__ */
