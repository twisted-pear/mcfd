#ifndef __MCFD_NET_H__
#define __MCFD_NET_H__

#include "mcfd_crypto.h"

void clear_buffers(void);
int crypt_to_plain(int crypt_sock, int plain_sock, mcfd_cipher *c_dec);
int plain_to_crypt(int plain_sock, int crypt_sock, mcfd_cipher *c_enc);

int create_listen_socket(int *sock, const char *addr, const char *port);
int connect_to_server(int *sock, const char *addr, const char *port);

#endif /* __MCFD_NET_H__ */
