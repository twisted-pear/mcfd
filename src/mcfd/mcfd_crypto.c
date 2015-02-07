#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_crypto.h"
#include "spongewrap.h"
#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>

#define SPONGEWRAP_RATE 1024
static_assert(MCFD_BLOCK_SIZE + KECCAKPAD_10_1_MIN_BIT_LEN
		+ 1 /* for spongewrap's frame bit */ <= SPONGEWRAP_RATE,
		"SPONGEWRAP_RATE too small");

struct mcfd_cipher_t {
	enum { CIPHER_READY = 0, CIPHER_BROKEN } state;
	spongewrap *w;
	unsigned char nonce[MCFD_NONCE_BYTES];
};

static void break_cipher(mcfd_cipher *cipher)
{
	assert(cipher != NULL);
	assert(cipher->w != NULL);

	keccakPad_10_1_free(cipher->w->p);
	keccakF_1600_free(cipher->w->f);
	spongewrap_free(cipher->w);

	cipher->state = CIPHER_BROKEN;
	cipher->w = NULL;

	explicit_bzero(cipher->nonce, sizeof(cipher->nonce));
}

static void nonce_succ(unsigned char *nonce)
{
	unsigned char carry = 1;

	size_t i;
	for (i = 0; i < MCFD_NONCE_BYTES; i++) {
		nonce[i] += carry;

		/* check for 1-bits */
		unsigned char accum = nonce[i];
		accum = (accum >> 4) | (accum & 0x0F);
		accum = (accum >> 2) | (accum & 0x03);
		accum = (accum >> 1) | (accum & 0x01);
		assert((accum == 0) | (accum == 1));

		carry &= ~accum;
		assert((carry == 0) | (carry == 1));
	}
}

mcfd_cipher *mcfd_cipher_init(const unsigned char *init_nonce, const unsigned char *key)
{
	assert(key != NULL);

	permutation *f = keccakF_1600_init();
	if (f == NULL) {
		goto permutation_fail;
	}

	pad *p = keccakPad_10_1_init(SPONGEWRAP_RATE);
	if (p == NULL) {
		goto pad_fail;
	}

	spongewrap *w = spongewrap_init(f, p, SPONGEWRAP_RATE, MCFD_BLOCK_SIZE / 8, key,
			MCFD_KEY_BYTES);
	if (w == NULL) {
		goto spongewrap_fail;
	}

	mcfd_cipher *cipher = malloc(sizeof(mcfd_cipher));
	if (cipher == NULL) {
		goto cipher_fail;
	}

	cipher->state = CIPHER_READY;
	cipher->w = w;

	if (mcfd_cipher_set_nonce(cipher, init_nonce) != 0) {
		assert(0);
		abort();
	}

	return cipher;

cipher_fail:
	spongewrap_free(w);
spongewrap_fail:
	keccakPad_10_1_free(p);
pad_fail:
	keccakF_1600_free(f);
permutation_fail:

	return NULL;
}

void mcfd_cipher_free(mcfd_cipher *cipher)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_BROKEN) {
		break_cipher(cipher);
	}

	free(cipher);
}

int mcfd_cipher_set_nonce(mcfd_cipher *cipher, const unsigned char *nonce)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_READY) {
		return 1;
	}

	if (nonce == NULL) {
		memset(cipher->nonce, 0, sizeof(cipher->nonce));
	} else {
		memcpy(cipher->nonce, nonce, sizeof(cipher->nonce));
	}

	return 0;
}

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_READY) {
		return 1;
	}

	assert(cipher->w != NULL);

	nonce_succ(cipher->nonce);

	if (spongewrap_wrap(cipher->w, cipher->nonce, sizeof(cipher->nonce), plaintext,
				plaintext_bytes, ciphertext, tag, MCFD_TAG_BYTES)
			!= CONSTR_SUCCESS) {
		break_cipher(cipher);

		return 1;
	}

	return 0;
}

int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_READY) {
		return 1;
	}

	assert(cipher->w != NULL);

	nonce_succ(cipher->nonce);

	if (spongewrap_unwrap(cipher->w, cipher->nonce, sizeof(cipher->nonce), ciphertext,
				ciphertext_bytes, tag, MCFD_TAG_BYTES, plaintext)
			!= CONSTR_SUCCESS) {
		break_cipher(cipher);

		return 1;
	}

	return 0;
}
