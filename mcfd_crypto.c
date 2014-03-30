#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "mcfd_crypto.h"
#include "spongewrap.h"
#include "KeccakF-1600.h"
#include "KeccakPad_10_1.h"

#define SPONGEWRAP_RATE 576

struct mcfd_cipher_t {
	spongewrap *w;
	/* FIXME: Probably not long enough. */
	uint64_t nonce;
};

mcfd_cipher *mcfd_cipher_init(const unsigned char *init_nonce, const unsigned char *key)
{
	assert(key != NULL);
	assert(init_nonce != NULL);

	permutation *f = keccakF_1600_init();
	if (f == NULL) {
		goto permutation_fail;
	}

	pad *p = keccakPad_10_1_init(SPONGEWRAP_RATE);
	if (p == NULL) {
		goto pad_fail;
	}

	spongewrap *w = spongewrap_init(f, p, SPONGEWRAP_RATE, MCFD_BLOCK_SIZE / 8, key,
			MCFD_KEY_BITS / 8);
	if (w == NULL) {
		goto spongewrap_fail;
	}

	mcfd_cipher *cipher = malloc(sizeof(mcfd_cipher));
	if (cipher == NULL) {
		goto cipher_fail;
	}

	cipher->w = w;
	cipher->nonce = (uint64_t) *init_nonce;

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
	assert(cipher->w != NULL);

	keccakPad_10_1_free(cipher->w->p);
	keccakF_1600_free(cipher->w->f);
	spongewrap_free(cipher->w);

	cipher->nonce = 0;

	free(cipher);
}

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag)
{
	assert(cipher != NULL);

	cipher->nonce++;

	return spongewrap_wrap(cipher->w, (unsigned char *) &cipher->nonce,
			sizeof(cipher->nonce), plaintext, plaintext_bytes, ciphertext,
			tag, MCFD_TAG_BITS / 8);
}

int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext)
{
	assert(cipher != NULL);

	cipher->nonce++;

	return spongewrap_unwrap(cipher->w, (unsigned char *) &cipher->nonce,
			sizeof(cipher->nonce), ciphertext, ciphertext_bytes, tag,
			MCFD_TAG_BITS / 8, plaintext);
}
