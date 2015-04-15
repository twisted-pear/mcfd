#ifndef __MCFD_AUTH_H__
#define __MCFD_AUTH_H__

#include <sys/socket.h>
#include <sys/types.h>

#include "curve25519.h"
#include "mcfd_cipher.h"

int mcfd_auth_server(int crypt_sock, mcfd_cipher *c_auth, unsigned char *key_enc,
		unsigned char *key_dec, unsigned char *nonce_enc,
		unsigned char *nonce_dec);
int mcfd_auth_client(int crypt_sock, mcfd_cipher *c_auth, unsigned char *key_enc,
		unsigned char *key_dec, unsigned char *nonce_enc,
		unsigned char *nonce_dec);

typedef struct mcfd_auth_context_t mcfd_auth_context;

#define CHALLENGE_BYTES MCFD_TAG_BYTES

#define MCFD_AUTH_RANDOM_BYTES (CURVE25519_PRIVATE_BYTES + CURVE25519_PRIVATE_BYTES + \
		(MCFD_NONCE_BYTES / 2) + (MCFD_NONCE_BYTES / 2) + CHALLENGE_BYTES)
mcfd_auth_context *mcfd_auth_init(const unsigned char *random_in);
void mcfd_auth_free(mcfd_auth_context *ctx);

#define AUTH_MSG_SIZE (CHALLENGE_BYTES * 2 + CURVE25519_PUBLIC_BYTES * 2 + \
		MCFD_NONCE_BYTES)

#define MCFD_AUTH_PHASE1_SERVER_OUT_BYTES CHALLENGE_BYTES
int mcfd_auth_phase1_server(mcfd_auth_context *ctx, unsigned char *out);

#define MCFD_AUTH_PHASE2_SERVER_IN_BYTES (AUTH_MSG_SIZE + MCFD_TAG_BYTES)
#define MCFD_AUTH_PHASE2_SERVER_OUT_BYTES (AUTH_MSG_SIZE + MCFD_TAG_BYTES)
int mcfd_auth_phase2_server(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in, unsigned char *out);

#define MCFD_AUTH_PHASE1_CLIENT_IN_BYTES CHALLENGE_BYTES
#define MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES (AUTH_MSG_SIZE + MCFD_TAG_BYTES)
int mcfd_auth_phase1_client(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in, unsigned char *out);

#define MCFD_AUTH_PHASE2_CLIENT_IN_BYTES (AUTH_MSG_SIZE + MCFD_TAG_BYTES)
int mcfd_auth_phase2_client(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in);

#endif /* __MCFD_AUTH_H__ */
