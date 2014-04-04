#include <errno.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_auth.h"
#include "mcfd_common.h"
#include "mcfd_crypto.h"
#include "mcfd_net.h"

#define CHALLENGE_BYTES MCFD_NONCE_BYTES

/* These fields are never explicitly cleared, they don't have to be secret. */
static unsigned char client_challenge[CHALLENGE_BYTES];
static unsigned char server_challenge[CHALLENGE_BYTES];

struct auth_msg_t {
	unsigned char challenge1[CHALLENGE_BYTES];
	unsigned char challenge2[CHALLENGE_BYTES];
	unsigned char half_key[MCFD_KEY_BYTES / 2];
	unsigned char half_nonce[MCFD_NONCE_BYTES / 2];
} __attribute__((packed));

static struct auth_msg_t auth_msg;

/* You must not use key or nonce unless this function returns 0. */
int mcfd_auth_server(int crypt_sock, mcfd_cipher *c_enc, mcfd_cipher *c_dec,
		unsigned char *key, unsigned char *nonce)
{
	assert(crypt_sock != -1);
	assert(c_enc != NULL);
	assert(c_dec != NULL);
	assert(key != NULL);
	assert(nonce != NULL);

	/* Create first halves of new key and nonce. */
	if (mcfd_get_random(key, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_get_random(nonce, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}

	/* Create server challenge */
	if (mcfd_get_random(server_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Send challenge to client */
	/* TODO: determine if we have to consider signals here */
	if (send(crypt_sock, server_challenge, CHALLENGE_BYTES, MSG_NOSIGNAL)
			!= CHALLENGE_BYTES) {
		print_err("send server challenge", strerror(errno));
		return 1;
	}

	/* TODO: do a timeout here. */
	/* Receive client reply and check server challenge */
	if (recv_crypt(crypt_sock, c_dec, (unsigned char *) &auth_msg,
				sizeof(auth_msg)) != 0) {
		return 1;
	}

	if (const_cmp(server_challenge, auth_msg.challenge2, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Copy second halves of new key and nonce. */
	memcpy(key + (MCFD_KEY_BYTES / 2), auth_msg.half_key, MCFD_KEY_BYTES / 2);
	memcpy(nonce + (MCFD_NONCE_BYTES / 2), auth_msg.half_nonce, MCFD_NONCE_BYTES / 2);

	/* Encrypt challenges and send to client */
	memcpy(client_challenge, auth_msg.challenge1, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge1, server_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge2, client_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.half_key, key, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_nonce, nonce, MCFD_NONCE_BYTES / 2);

	if (send_crypt(crypt_sock, c_enc, (unsigned char *) &auth_msg,
				sizeof(auth_msg) )!= 0) {
		return 1;
	}

	/* Destroy old partial key and nonce. */
	memset(&auth_msg, 0, sizeof(auth_msg));

	return 0;
}

/* You must not use key or nonce unless this function returns 0. */
int mcfd_auth_client(int crypt_sock, mcfd_cipher *c_enc, mcfd_cipher *c_dec,
		unsigned char *key, unsigned char *nonce)
{
	assert(crypt_sock != -1);
	assert(c_enc != NULL);
	assert(c_dec != NULL);
	assert(key != NULL);
	assert(nonce != NULL);

	/* Create second halves of new key and nonce. */
	if (mcfd_get_random(key + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_get_random(nonce + MCFD_NONCE_BYTES / 2, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}

	/* Create client callenge */
	if (mcfd_get_random(client_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Receive server callenge */
	/* TODO: do a timeout here. */
	/* TODO: determine if we have to consider signals here */
	if (recv(crypt_sock, server_challenge, CHALLENGE_BYTES, MSG_WAITALL)
			!= CHALLENGE_BYTES) {
		print_err("receive server challenge", strerror(errno));
		return 1;
	}

	/* Encrypt challenges and send to server */
	memcpy(auth_msg.challenge1, client_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge2, server_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.half_key, key + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_nonce, nonce + MCFD_NONCE_BYTES / 2, MCFD_NONCE_BYTES / 2);

	if (send_crypt(crypt_sock, c_enc, (unsigned char *) &auth_msg,
				sizeof(auth_msg) )!= 0) {
		return 1;
	}

	/* Receive server reply and check challenges */
	/* TODO: do a timeout here. */
	if (recv_crypt(crypt_sock, c_dec, (unsigned char *) &auth_msg,
				sizeof(auth_msg)) != 0) {
		return 1;
	}

	if (const_cmp(client_challenge, auth_msg.challenge2, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	if (const_cmp(server_challenge, auth_msg.challenge1, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Copy first halves of new key and nonce. */
	memcpy(key, auth_msg.half_key, MCFD_KEY_BYTES / 2);
	memcpy(nonce, auth_msg.half_nonce, MCFD_NONCE_BYTES / 2);

	/* Destroy old partial key and nonce. */
	memset(&auth_msg, 0, sizeof(auth_msg));

	return 0;
}
