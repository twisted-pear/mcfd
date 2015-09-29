#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <mcfd_config.h>

#include "crypto_helpers.h"
#include "mcfd_kdf.h"

#include <nacl/crypto_hash.h>

#ifndef USE_NACL
#	error "USE_NACL not set, but mcfd_kdf_nacl used"
#endif /* USE_NACL */

int mcfd_kdf(const char *pass, const size_t pass_len, const unsigned char *salt,
		const size_t iterations, unsigned char *key, const size_t key_bits)
{
	if (pass == NULL || pass_len == 0) {
		return 1;
	}

	if (key == NULL || key_bits == 0 || key_bits > crypto_hash_BYTES * 8) {
		return 1;
	}

	size_t iter = iterations > 0 ? iterations : MCFD_KDF_DEF_ITERATIONS;

	size_t mlen;
	if (salt != NULL) {
		/* FIXME: should use a builtin where available */
		if (SIZE_MAX - pass_len <= MCFD_SALT_BYTES) {
			return 1;
		}
		mlen = pass_len + MCFD_SALT_BYTES;
	} else {
		mlen = pass_len;
	}

	unsigned char *m = malloc(mlen);
	if (m == NULL) {
		return 1;
	}

	int ret = 1;

	memcpy(m, pass, pass_len);

	if (salt != NULL) {
		assert(mlen == pass_len + MCFD_SALT_BYTES);
		memcpy(m + pass_len, salt, MCFD_SALT_BYTES);
	}

	assert(iter > 0);

	static unsigned char kdf_buf[crypto_hash_BYTES];

	if (crypto_hash(kdf_buf, m, mlen) != 0) {
		goto sanitized_exit;
	}

	size_t i;
	for (i = 0; i < iter - 1; i++) {
		if (crypto_hash(kdf_buf, kdf_buf, crypto_hash_BYTES) != 0) {
			goto sanitized_exit;
		}
	}

	memcpy(key, kdf_buf, key_bits / 8);

	ret = 0;

sanitized_exit:
	explicit_bzero(kdf_buf, crypto_hash_BYTES);

	explicit_bzero(m, mlen);
	free(m);

	return ret;
}
