#ifndef __MCFD_AUTH_H__
#define __MCFD_AUTH_H__

#include <sys/socket.h>
#include <sys/types.h>

#include "mcfd_crypto.h"

int mcfd_auth_server(int crypt_sock, mcfd_cipher *c_enc, mcfd_cipher *c_dec,
		unsigned char *key, unsigned char *nonce_enc, unsigned char *nonce_dec);
int mcfd_auth_client(int crypt_sock, mcfd_cipher *c_enc, mcfd_cipher *c_dec,
		unsigned char *key, unsigned char *nonce_enc, unsigned char *nonce_dec);

#endif /* __MCFD_AUTH_H__ */
