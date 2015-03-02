#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_auth.h"
#include "mcfd_common.h"
#include "mcfd_cipher.h"
#include "mcfd_net.h"
#include "mcfd_random.h"

#define CHALLENGE_BYTES MCFD_TAG_BYTES

/* These fields are never explicitly cleared, they don't have to be secret. */
static unsigned char client_challenge[CHALLENGE_BYTES];
static unsigned char server_challenge[CHALLENGE_BYTES];
static unsigned char auth_enc_nonce[MCFD_NONCE_BYTES];

struct auth_msg_t {
	unsigned char challenge1[CHALLENGE_BYTES];
	unsigned char challenge2[CHALLENGE_BYTES];
	unsigned char half_key_cs[MCFD_KEY_BYTES / 2];
	unsigned char half_key_sc[MCFD_KEY_BYTES / 2];
	unsigned char half_nonce_cs[MCFD_NONCE_BYTES / 2];
	unsigned char half_nonce_sc[MCFD_NONCE_BYTES / 2];
} __attribute__((packed));

static struct auth_msg_t auth_msg;
static_assert(MCFD_NET_CRYPT_BUF_SIZE >= sizeof(auth_msg),
		"MCFD_NET_CRYPT_BUF_SIZE too small");

static_assert(MCFD_RANDOM_MAX >= ((MCFD_KEY_BYTES / 2) + (MCFD_KEY_BYTES / 2) +
			(MCFD_NONCE_BYTES / 2) + (MCFD_NONCE_BYTES / 2) + MCFD_NONCE_BYTES
			+ CHALLENGE_BYTES),
		"MCFD_RANDOM_MAX too small");

static_assert(MCFD_KEY_BYTES % 2 == 0, "Odd key length");
static_assert(MCFD_NONCE_BYTES % 2 == 0, "Odd nonce length");

/* You must not use key or nonces unless this function returns 0. */
int mcfd_auth_server(int crypt_sock, mcfd_cipher *c_auth, unsigned char *key_enc,
		unsigned char *key_dec, unsigned char *nonce_enc,
		unsigned char *nonce_dec)
{
	assert(crypt_sock != -1);
	assert(c_auth != NULL);
	assert(key_enc != NULL);
	assert(key_dec != NULL);
	assert(nonce_enc != NULL);
	assert(nonce_dec != NULL);

	/* Create first halves of new keys and nonces. */
	if (mcfd_random_get(key_enc, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(key_dec, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(nonce_enc, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(nonce_dec, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}

	/* Create server challenge */
	if (mcfd_random_get(server_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Send challenge to client */
	if (net_send(crypt_sock, server_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Receive nonce from client */
	/* TODO: do a timeout here. */
	if (net_recv(crypt_sock, auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		return 1;
	}
	if (mcfd_cipher_set_nonce(c_auth, auth_enc_nonce) != 0) {
		assert(0);
		abort();
	}

	/* Receive client reply and check server challenge */
	/* TODO: do a timeout here. */
	if (recv_crypt(crypt_sock, c_auth, (unsigned char *) &auth_msg,
				sizeof(auth_msg)) != 0) {
		return 1;
	}

	if (timingsafe_bcmp(server_challenge, auth_msg.challenge2, CHALLENGE_BYTES)
			!= 0) {
		return 1;
	}

	/* Copy second halves of new keys and nonces. */
	memcpy(key_enc + (MCFD_KEY_BYTES / 2), auth_msg.half_key_sc, MCFD_KEY_BYTES / 2);
	memcpy(key_dec + (MCFD_KEY_BYTES / 2), auth_msg.half_key_cs, MCFD_KEY_BYTES / 2);
	memcpy(nonce_enc + (MCFD_NONCE_BYTES / 2), auth_msg.half_nonce_sc,
			MCFD_NONCE_BYTES / 2);
	memcpy(nonce_dec + (MCFD_NONCE_BYTES / 2), auth_msg.half_nonce_cs,
			MCFD_NONCE_BYTES / 2);

	memcpy(client_challenge, auth_msg.challenge1, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge1, server_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge2, client_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.half_key_sc, key_enc, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_key_cs, key_dec, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_nonce_sc, nonce_enc, MCFD_NONCE_BYTES / 2);
	memcpy(auth_msg.half_nonce_cs, nonce_dec, MCFD_NONCE_BYTES / 2);

	/* Encrypt challenges and send to client */
	if (send_crypt(crypt_sock, c_auth, (unsigned char *) &auth_msg,
				sizeof(auth_msg) )!= 0) {
		return 1;
	}

	/* Destroy old partial keys and nonces. */
	explicit_bzero(&auth_msg, sizeof(auth_msg));

	return 0;
}

/* You must not use key or nonces unless this function returns 0. */
int mcfd_auth_client(int crypt_sock, mcfd_cipher *c_auth, unsigned char *key_enc,
		unsigned char *key_dec, unsigned char *nonce_enc,
		unsigned char *nonce_dec)
{
	assert(crypt_sock != -1);
	assert(c_auth != NULL);
	assert(key_enc != NULL);
	assert(key_dec != NULL);
	assert(nonce_enc != NULL);
	assert(nonce_dec != NULL);

	/* Create second halves of new keys. */
	if (mcfd_random_get(key_enc + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(key_dec + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(nonce_enc + MCFD_NONCE_BYTES / 2, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}
	if (mcfd_random_get(nonce_dec + MCFD_NONCE_BYTES / 2, MCFD_NONCE_BYTES / 2) != 0) {
		return 1;
	}

	/* Create encryption nonce */
	if (mcfd_random_get(auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		return 1;
	}
	if (mcfd_cipher_set_nonce(c_auth, auth_enc_nonce) != 0) {
		assert(0);
		abort();
	}

	/* Create client callenge */
	if (mcfd_random_get(client_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	/* Receive server callenge */
	/* TODO: do a timeout here. */
	if (net_recv(crypt_sock, server_challenge, CHALLENGE_BYTES) != 0) {
		return 1;
	}

	memcpy(auth_msg.challenge1, client_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.challenge2, server_challenge, CHALLENGE_BYTES);
	memcpy(auth_msg.half_key_cs, key_enc + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_key_sc, key_dec + MCFD_KEY_BYTES / 2, MCFD_KEY_BYTES / 2);
	memcpy(auth_msg.half_nonce_cs, nonce_enc + MCFD_NONCE_BYTES / 2,
			MCFD_NONCE_BYTES / 2);
	memcpy(auth_msg.half_nonce_sc, nonce_dec + MCFD_NONCE_BYTES / 2,
			MCFD_NONCE_BYTES / 2);

	if (net_send(crypt_sock, auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		return 1;
	}

	/* Encrypt challenges and send to server */
	if (send_crypt(crypt_sock, c_auth, (unsigned char *) &auth_msg,
				sizeof(auth_msg) )!= 0) {
		return 1;
	}

	/* Receive server reply and check challenges */
	/* TODO: do a timeout here. */
	if (recv_crypt(crypt_sock, c_auth, (unsigned char *) &auth_msg,
				sizeof(auth_msg)) != 0) {
		return 1;
	}

	if (timingsafe_bcmp(client_challenge, auth_msg.challenge2, CHALLENGE_BYTES)
			!= 0) {
		return 1;
	}

	if (timingsafe_bcmp(server_challenge, auth_msg.challenge1, CHALLENGE_BYTES)
			!= 0) {
		return 1;
	}

	/* Copy first halves of new keys and nonces. */
	memcpy(key_enc, auth_msg.half_key_cs, MCFD_KEY_BYTES / 2);
	memcpy(key_dec, auth_msg.half_key_sc, MCFD_KEY_BYTES / 2);
	memcpy(nonce_enc, auth_msg.half_nonce_cs, MCFD_NONCE_BYTES / 2);
	memcpy(nonce_dec, auth_msg.half_nonce_sc, MCFD_NONCE_BYTES / 2);

	/* Destroy old partial keys and nonces. */
	explicit_bzero(&auth_msg, sizeof(auth_msg));

	return 0;
}
