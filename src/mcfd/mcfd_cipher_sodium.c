#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <sodium/crypto_secretbox.h>

#include "crypto_helpers.h"
#include "mcfd_cipher.h"

#ifndef USE_SODIUM
#	error "USE_SODIUM not set, but mcfd_cipher_sodium used"
#endif /* USE_SODIUM */

static_assert(MCFD_TAG_BITS == crypto_secretbox_ZEROBYTES * 8, "MCFD_TAG_BITS invalid");
static_assert(MCFD_TAG_BYTES == crypto_secretbox_ZEROBYTES, "MCFD_TAG_BYTES invalid");

static_assert(MCFD_KEY_BITS == crypto_secretbox_KEYBYTES * 8, "MCFD_KEY_BITS invalid");
static_assert(MCFD_KEY_BYTES == crypto_secretbox_KEYBYTES, "MCFD_KEY_BYTES invalid");

static_assert(MCFD_NONCE_BITS == crypto_secretbox_NONCEBYTES * 8,
		"MCFD_NONCE_BITS invalid");
static_assert(MCFD_NONCE_BYTES == crypto_secretbox_NONCEBYTES,
		"MCFD_NONCE_BYTES invalid");

struct mcfd_cipher_t {
	enum { CIPHER_READY = 0, CIPHER_BROKEN } state;
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char key[crypto_secretbox_KEYBYTES];
};

static void break_cipher(mcfd_cipher *cipher)
{
	assert(cipher != NULL);

	cipher->state = CIPHER_BROKEN;

	explicit_bzero(cipher->nonce, sizeof(cipher->nonce));
	explicit_bzero(cipher->key, sizeof(cipher->key));
}

static void nonce_succ(unsigned char *nonce)
{
	unsigned char carry = 1;

	size_t i;
	for (i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
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
	if (key == NULL) {
		return NULL;
	}

	mcfd_cipher *cipher = malloc(sizeof(mcfd_cipher));
	if (cipher == NULL) {
		return NULL;
	}

	cipher->state = CIPHER_READY;

	if (init_nonce == NULL) {
		memset(cipher->nonce, 0, sizeof(cipher->nonce));
	} else {
		memcpy(cipher->nonce, init_nonce, sizeof(cipher->nonce));
	}

	memcpy(cipher->key, key, sizeof(cipher->key));

	return cipher;
}

void mcfd_cipher_free(mcfd_cipher *cipher)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_BROKEN) {
		break_cipher(cipher);
	}

	free(cipher);
}

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_READY) {
		return 1;
	}

	/* FIXME: should use a builtin where available */
	if (SIZE_MAX - plaintext_bytes <= crypto_secretbox_ZEROBYTES) {
			return 1;
	}
	size_t mlen = plaintext_bytes + crypto_secretbox_ZEROBYTES;

	unsigned char *m = malloc(mlen);
	if (m == NULL) {
		return 1;
	}

	unsigned char *c = malloc(mlen);
	if (c == NULL) {
		free(m);
		return 1;
	}

	nonce_succ(cipher->nonce);

	int ret = 1;

	memset(m, 0, crypto_secretbox_ZEROBYTES);
	memcpy(m + crypto_secretbox_ZEROBYTES, plaintext, plaintext_bytes);

	if (crypto_secretbox(c, m, mlen, cipher->nonce, cipher->key) != 0) {
		break_cipher(cipher);

		goto sanitized_exit;
	}

	memcpy(ciphertext, c, plaintext_bytes);
	memcpy(tag, c + plaintext_bytes, crypto_secretbox_ZEROBYTES);

	ret = 0;

sanitized_exit:
	explicit_bzero(m, mlen);
	free(m);

	explicit_bzero(c, mlen);
	free(c);

	return ret;
}

int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext)
{
	assert(cipher != NULL);

	if (cipher->state != CIPHER_READY) {
		return 1;
	}

	/* FIXME: should use a builtin where available */
	if (SIZE_MAX - ciphertext_bytes <= crypto_secretbox_ZEROBYTES) {
			return 1;
	}
	size_t clen = ciphertext_bytes + crypto_secretbox_ZEROBYTES;

	unsigned char *m = malloc(clen);
	if (m == NULL) {
		return 1;
	}

	unsigned char *c = malloc(clen);
	if (c == NULL) {
		free(m);
		return 1;
	}

	nonce_succ(cipher->nonce);

	int ret = 1;

	memcpy(c, ciphertext, ciphertext_bytes);
	memcpy(c + ciphertext_bytes, tag, crypto_secretbox_ZEROBYTES);

	size_t i;
	for (i = 0; i < crypto_secretbox_BOXZEROBYTES; i++) {
		if (c[i] != 0) {
			break_cipher(cipher);

			goto sanitized_exit;
		}
	}

	if (crypto_secretbox_open(m, c, clen, cipher->nonce, cipher->key) != 0) {
		break_cipher(cipher);

		goto sanitized_exit;
	}

	memcpy(plaintext, m + crypto_secretbox_ZEROBYTES, ciphertext_bytes);

	ret = 0;

sanitized_exit:
	explicit_bzero(m, clen);
	free(m);

	explicit_bzero(c, clen);
	free(c);

	return ret;
}
