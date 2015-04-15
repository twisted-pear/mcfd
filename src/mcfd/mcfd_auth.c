#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "curve25519.h"
#include "mcfd_auth.h"
#include "mcfd_common.h"
#include "mcfd_cipher.h"
#include "mcfd_kdf.h"
#include "mcfd_net.h"
#include "mcfd_random.h"

static_assert(MCFD_KEY_BYTES % 2 == 0, "Odd key length");
static_assert(MCFD_NONCE_BYTES % 2 == 0, "Odd nonce length");

typedef struct mcfd_auth_context_t {
	enum { AUTH_CONTEXT_PHASE1 = 0, AUTH_CONTEXT_PHASE2_CLIENT,
		AUTH_CONTEXT_PHASE2_SERVER, AUTH_CONTEXT_DONE_CLIENT,
		AUTH_CONTEXT_DONE_SERVER, AUTH_CONTEXT_BROKEN
	} state;
	unsigned char challenge_local[CHALLENGE_BYTES];
	unsigned char challenge_remote[CHALLENGE_BYTES];
	unsigned char private_cs[CURVE25519_PRIVATE_BYTES];
	unsigned char private_sc[CURVE25519_PRIVATE_BYTES];
	unsigned char public_cs[CURVE25519_PUBLIC_BYTES];
	unsigned char public_sc[CURVE25519_PUBLIC_BYTES];
	unsigned char half_nonce_cs_local[MCFD_NONCE_BYTES / 2];
	unsigned char half_nonce_sc_local[MCFD_NONCE_BYTES / 2];
	unsigned char half_nonce_cs_remote[MCFD_NONCE_BYTES / 2];
	unsigned char half_nonce_sc_remote[MCFD_NONCE_BYTES / 2];
} mcfd_auth_context;

static void break_auth_context(mcfd_auth_context *ctx)
{
	explicit_bzero(ctx, sizeof(mcfd_auth_context));
	ctx->state = AUTH_CONTEXT_BROKEN;
}

static_assert(MCFD_RANDOM_MAX >= MCFD_AUTH_RANDOM_BYTES, "MCFD_RANDOM_MAX too small");

mcfd_auth_context *mcfd_auth_init(const unsigned char *random_in)
{
	if (random_in == NULL) {
		return NULL;
	}

	mcfd_auth_context *ctx = malloc(sizeof(mcfd_auth_context));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->state = AUTH_CONTEXT_PHASE1;

	const unsigned char *random_cur = random_in;

	memcpy(ctx->challenge_local, random_cur, CHALLENGE_BYTES);
	random_cur += CHALLENGE_BYTES;

	/* Create local private keys. */
	memcpy(ctx->private_cs, random_cur, CURVE25519_PRIVATE_BYTES);
	random_cur += CURVE25519_PRIVATE_BYTES;
	curve25519_clamp(ctx->private_cs);

	memcpy(ctx->private_sc, random_cur, CURVE25519_PRIVATE_BYTES);
	random_cur += CURVE25519_PRIVATE_BYTES;
	curve25519_clamp(ctx->private_sc);

	/* Create local half nonces. */
	memcpy(ctx->half_nonce_cs_local, random_cur, MCFD_NONCE_BYTES / 2);
	random_cur += MCFD_NONCE_BYTES / 2;

	memcpy(ctx->half_nonce_sc_local, random_cur, MCFD_NONCE_BYTES / 2);
	random_cur += MCFD_NONCE_BYTES / 2;

	return ctx;
}

void mcfd_auth_free(mcfd_auth_context *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->state != AUTH_CONTEXT_BROKEN) {
		break_auth_context(ctx);
	}

	free(ctx);
}

struct auth_msg_t {
	unsigned char challenge1[CHALLENGE_BYTES];
	unsigned char challenge2[CHALLENGE_BYTES];
	unsigned char half_key_cs[CURVE25519_PUBLIC_BYTES];
	unsigned char half_key_sc[CURVE25519_PUBLIC_BYTES];
	unsigned char half_nonce_cs[MCFD_NONCE_BYTES / 2];
	unsigned char half_nonce_sc[MCFD_NONCE_BYTES / 2];
} __attribute__((packed));

static_assert(AUTH_MSG_SIZE == sizeof(struct auth_msg_t), "AUTH_MSG_SIZE wrong");

int mcfd_auth_phase1_server(mcfd_auth_context *ctx, unsigned char *out)
{
	if (ctx == NULL || out == NULL) {
		return 1;
	}

	if (ctx->state != AUTH_CONTEXT_PHASE1) {
		return 1;
	}

	memcpy(out, ctx->challenge_local, CHALLENGE_BYTES);

	ctx->state = AUTH_CONTEXT_PHASE2_SERVER;

	return 0;
}

int mcfd_auth_phase2_server(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in, unsigned char *out)
{
	if (ctx == NULL || c_auth == NULL || in == NULL || out == NULL) {
		return 1;
	}

	if (ctx->state != AUTH_CONTEXT_PHASE2_SERVER) {
		return 1;
	}

	struct auth_msg_t *auth_msg = calloc(1, sizeof(struct auth_msg_t));
	if (auth_msg == NULL) {
		return 1;
	}

	if (mcfd_cipher_decrypt(c_auth, in, sizeof(struct auth_msg_t),
				in + sizeof(struct auth_msg_t),
				(unsigned char *) auth_msg) != 0) {
		goto fail;
	}

	if (timingsafe_bcmp(ctx->challenge_local, auth_msg->challenge2, CHALLENGE_BYTES)
			!= 0) {
		goto fail;
	}

	/* Store remote public keys. */
	memcpy(ctx->public_cs, auth_msg->half_key_cs, CURVE25519_PUBLIC_BYTES);
	memcpy(ctx->public_sc, auth_msg->half_key_sc, CURVE25519_PUBLIC_BYTES);

	/* Store remote half nonces. */
	memcpy(ctx->half_nonce_cs_remote, auth_msg->half_nonce_cs, MCFD_NONCE_BYTES / 2);
	memcpy(ctx->half_nonce_sc_remote, auth_msg->half_nonce_sc, MCFD_NONCE_BYTES / 2);

	/* Store remote challenge. */
	memcpy(ctx->challenge_remote, auth_msg->challenge1, CHALLENGE_BYTES);

	memcpy(auth_msg->challenge1, ctx->challenge_local, CHALLENGE_BYTES);
	memcpy(auth_msg->challenge2, ctx->challenge_remote, CHALLENGE_BYTES);
	curve25519_public(ctx->private_cs, auth_msg->half_key_cs);
	curve25519_public(ctx->private_sc, auth_msg->half_key_sc);
	memcpy(auth_msg->half_nonce_cs, ctx->half_nonce_cs_local, MCFD_NONCE_BYTES / 2);
	memcpy(auth_msg->half_nonce_sc, ctx->half_nonce_sc_local, MCFD_NONCE_BYTES / 2);

	if (mcfd_cipher_encrypt(c_auth, (unsigned char *) auth_msg,
				sizeof(struct auth_msg_t), out,
				out + sizeof(struct auth_msg_t)) != 0) {
		goto fail;
	}

	explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
	free(auth_msg);

	ctx->state = AUTH_CONTEXT_DONE_SERVER;

	return 0;

fail:
	break_auth_context(ctx);

	explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
	free(auth_msg);

	return 1;
}

int mcfd_auth_phase1_client(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in, unsigned char *out)
{
	if (ctx == NULL || c_auth == NULL || in == NULL || out == NULL) {
		return 1;
	}

	if (ctx->state != AUTH_CONTEXT_PHASE1) {
		return 1;
	}

	struct auth_msg_t *auth_msg = calloc(1, sizeof(struct auth_msg_t));
	if (auth_msg == NULL) {
		return 1;
	}

	/* Store remote challenge. */
	memcpy(ctx->challenge_remote, in, CHALLENGE_BYTES);

	memcpy(auth_msg->challenge1, ctx->challenge_local, CHALLENGE_BYTES);
	memcpy(auth_msg->challenge2, ctx->challenge_remote, CHALLENGE_BYTES);
	curve25519_public(ctx->private_cs, auth_msg->half_key_cs);
	curve25519_public(ctx->private_sc, auth_msg->half_key_sc);
	memcpy(auth_msg->half_nonce_cs, ctx->half_nonce_cs_local, MCFD_NONCE_BYTES / 2);
	memcpy(auth_msg->half_nonce_sc, ctx->half_nonce_sc_local, MCFD_NONCE_BYTES / 2);

	if (mcfd_cipher_encrypt(c_auth, (unsigned char *) auth_msg,
				sizeof(struct auth_msg_t), out,
				out + sizeof(struct auth_msg_t)) != 0) {
		break_auth_context(ctx);
		explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
		free(auth_msg);
		return 1;
	}

	explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
	free(auth_msg);

	ctx->state = AUTH_CONTEXT_PHASE2_CLIENT;

	return 0;
}

int mcfd_auth_phase2_client(mcfd_auth_context *ctx, mcfd_cipher *c_auth,
		unsigned char *in)
{
	if (ctx == NULL || c_auth == NULL || in == NULL) {
		return 1;
	}

	if (ctx->state != AUTH_CONTEXT_PHASE2_CLIENT) {
		return 1;
	}

	struct auth_msg_t *auth_msg = calloc(1, sizeof(struct auth_msg_t));
	if (auth_msg == NULL) {
		return 1;
	}

	if (mcfd_cipher_decrypt(c_auth, in, sizeof(struct auth_msg_t),
				in + sizeof(struct auth_msg_t),
				(unsigned char *) auth_msg) != 0) {
		goto fail;
	}

	if (timingsafe_bcmp(ctx->challenge_local, auth_msg->challenge2, CHALLENGE_BYTES)
			!= 0) {
		goto fail;
	}

	if (timingsafe_bcmp(ctx->challenge_remote, auth_msg->challenge1, CHALLENGE_BYTES)
			!= 0) {
		goto fail;
	}

	/* Store remote public keys. */
	memcpy(ctx->public_cs, auth_msg->half_key_cs, CURVE25519_PUBLIC_BYTES);
	memcpy(ctx->public_sc, auth_msg->half_key_sc, CURVE25519_PUBLIC_BYTES);

	/* Store remote half nonces. */
	memcpy(ctx->half_nonce_cs_remote, auth_msg->half_nonce_cs, MCFD_NONCE_BYTES / 2);
	memcpy(ctx->half_nonce_sc_remote, auth_msg->half_nonce_sc, MCFD_NONCE_BYTES / 2);

	explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
	free(auth_msg);

	ctx->state = AUTH_CONTEXT_DONE_CLIENT;

	return 0;

fail:
	break_auth_context(ctx);

	explicit_bzero(auth_msg, sizeof(struct auth_msg_t));
	free(auth_msg);

	return 1;
}

int mcfd_auth_finish(mcfd_auth_context *ctx, unsigned char *key_sc,
		unsigned char *key_cs, unsigned char *nonce_sc,
		unsigned char *nonce_cs)
{
	if (ctx == NULL || key_sc == NULL || key_cs == NULL || nonce_sc == NULL ||
			nonce_cs == NULL) {
		return 1;
	}

	if (ctx->state != AUTH_CONTEXT_DONE_SERVER &&
			ctx->state != AUTH_CONTEXT_DONE_CLIENT) {
		return 1;
	}

	unsigned char *shared = malloc(CURVE25519_SHARED_BYTES * 2);
	if (shared == NULL) {
		return 1;
	}

	int ret = 1;

	/* Create the shared secrets. */
	curve25519(shared, ctx->private_sc, ctx->public_sc);
	curve25519(shared + CURVE25519_SHARED_BYTES, ctx->private_cs, ctx->public_cs);

	if (mcfd_kdf((const char *) shared, CURVE25519_SHARED_BYTES, NULL, 1,
				key_sc, MCFD_KEY_BITS) != 0) {
		goto fail;
	}
	if (mcfd_kdf((const char *) shared + CURVE25519_SHARED_BYTES,
				CURVE25519_SHARED_BYTES, NULL, 1, key_cs, MCFD_KEY_BITS)
			!= 0) {
		explicit_bzero(key_sc, MCFD_KEY_BYTES);
		goto fail;
	}

	if (ctx->state == AUTH_CONTEXT_DONE_SERVER) {
		memcpy(nonce_sc, ctx->half_nonce_sc_local, MCFD_NONCE_BYTES / 2);
		memcpy(nonce_cs, ctx->half_nonce_cs_local, MCFD_NONCE_BYTES / 2);
		memcpy(nonce_sc + MCFD_NONCE_BYTES / 2, ctx->half_nonce_sc_remote,
				MCFD_NONCE_BYTES / 2);
		memcpy(nonce_cs + MCFD_NONCE_BYTES / 2, ctx->half_nonce_cs_remote,
				MCFD_NONCE_BYTES / 2);
	} else {
		memcpy(nonce_sc, ctx->half_nonce_sc_remote, MCFD_NONCE_BYTES / 2);
		memcpy(nonce_cs, ctx->half_nonce_cs_remote, MCFD_NONCE_BYTES / 2);
		memcpy(nonce_sc + MCFD_NONCE_BYTES / 2, ctx->half_nonce_sc_local,
				MCFD_NONCE_BYTES / 2);
		memcpy(nonce_cs + MCFD_NONCE_BYTES / 2, ctx->half_nonce_cs_local,
				MCFD_NONCE_BYTES / 2);
	}

	ret = 0;

fail:
	explicit_bzero(shared, CURVE25519_SHARED_BYTES * 2);
	free(shared);

	break_auth_context(ctx);

	return ret;
}


static_assert(MCFD_RANDOM_MAX >= (CURVE25519_PRIVATE_BYTES + CURVE25519_PRIVATE_BYTES +
			(MCFD_NONCE_BYTES / 2) + (MCFD_NONCE_BYTES / 2) + MCFD_NONCE_BYTES
			+ CHALLENGE_BYTES),
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

	int ret = 1;

	if (mcfd_random_get(auth_buf, MCFD_AUTH_RANDOM_BYTES) != 0) {
		return 1;
	}

	mcfd_auth_context *ctx = mcfd_auth_init(auth_buf);
	if (ctx == NULL) {
		explicit_bzero(auth_buf, AUTH_BUF_SIZE);
		return 1;
	}

	/* auth phase 1 */
	if (mcfd_auth_phase1_server(ctx, auth_buf) != 0) {
		goto fail;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_SERVER_OUT_BYTES)
			!= 0) {
		goto fail;
	}

	/* Receive nonce from client */
	/* TODO: do a timeout here. */
	unsigned char auth_enc_nonce[MCFD_NONCE_BYTES];
	if (net_recv(crypt_sock, auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		goto fail;
	}
	if (mcfd_cipher_set_nonce(c_auth, auth_enc_nonce) != 0) {
		assert(0);
		abort();
	}

	/* auth phase 2 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_SERVER_IN_BYTES) != 0) {
		goto fail;
	}
	if (mcfd_auth_phase2_server(ctx, c_auth, auth_buf, auth_buf) != 0) {
		goto fail;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_SERVER_OUT_BYTES)
			!= 0) {
		goto fail;
	}

	if (mcfd_auth_finish(ctx, key_enc, key_dec, nonce_enc, nonce_dec) != 0) {
		goto fail;
	}

	ret = 0;

fail:
	explicit_bzero(auth_buf, AUTH_BUF_SIZE);
	mcfd_auth_free(ctx);

	return ret;
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

	int ret = 1;
	
	if (mcfd_random_get(auth_buf, MCFD_AUTH_RANDOM_BYTES) != 0) {
		return 1;
	}

	mcfd_auth_context *ctx = mcfd_auth_init(auth_buf);
	if (ctx == NULL) {
		explicit_bzero(auth_buf, AUTH_BUF_SIZE);
		return 1;
	}

	/* Create encryption nonce */
	unsigned char auth_enc_nonce[MCFD_NONCE_BYTES];
	if (mcfd_random_get(auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		goto fail;
	}
	if (mcfd_cipher_set_nonce(c_auth, auth_enc_nonce) != 0) {
		assert(0);
		abort();
	}
	if (net_send(crypt_sock, auth_enc_nonce, MCFD_NONCE_BYTES) != 0) {
		goto fail;
	}

	/* auth phase 1 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_CLIENT_IN_BYTES) != 0) {
		goto fail;
	}
	if (mcfd_auth_phase1_client(ctx, c_auth, auth_buf, auth_buf) != 0) {
		goto fail;
	}
	if (net_send(crypt_sock, auth_buf, MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES) != 0) {
		goto fail;
	}

	/* auth phase 2 */
	if (net_recv(crypt_sock, auth_buf, MCFD_AUTH_PHASE2_CLIENT_IN_BYTES) != 0) {
		goto fail;
	}
	if (mcfd_auth_phase2_client(ctx, c_auth, auth_buf) != 0) {
		goto fail;
	}

	if (mcfd_auth_finish(ctx, key_dec, key_enc, nonce_dec, nonce_enc) != 0) {
		goto fail;
	}

	ret = 0;

fail:
	explicit_bzero(auth_buf, AUTH_BUF_SIZE);
	mcfd_auth_free(ctx);

	return ret;
}
