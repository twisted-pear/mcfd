#include <stdlib.h>

#include <assert.h>

#include <mcfd_config.h>

#include "crypto_helpers.h"
#include "mcfd_kdf.h"
#include "sponge.h"
#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>

#ifdef USE_NACL
#	error "USE_NACL set, but mcfd_kdf used"
#endif /* USE_NACL */

#define KDF_RATE 576

int mcfd_kdf(const char *pass, const size_t pass_len, const unsigned char *salt,
		const size_t iterations, unsigned char *key, const size_t key_bits)
{
	if (pass == NULL || pass_len == 0) {
		return 1;
	}

	if (key == NULL || key_bits == 0) {
		return 1;
	}

	size_t iter = iterations > 0 ? iterations : MCFD_KDF_DEF_ITERATIONS;

	int ret = 1;

	permutation *f = keccakF_1600_init();
	if (f == NULL) {
		goto permutation_fail;
	}

	pad *p = keccakPad_10_1_init(KDF_RATE);
	if (p == NULL) {
		goto pad_fail;
	}

    	sponge *sp = sponge_init(f, p, KDF_RATE);
	if (sp == NULL) {
		goto sponge_fail;
	}

	if (sponge_absorb(sp, (unsigned char *) pass, pass_len * 8) != CONSTR_SUCCESS) {
		goto absorb_fail;
	}

	if (salt != NULL) {
		if (sponge_absorb(sp, salt, MCFD_SALT_BITS) != CONSTR_SUCCESS) {
			goto absorb_fail;
		}
	}

	if (sponge_absorb_final(sp) != CONSTR_SUCCESS) {
		goto absorb_fail;
	}

	assert(iter > 0);

	static unsigned char kdf_buf[KDF_RATE / 8];

	size_t i;
	for (i = 0; i < iter - 1; i++) {
		if (sponge_squeeze(sp, kdf_buf, KDF_RATE) != CONSTR_SUCCESS) {
			goto squeeze_fail;
		}
	}

	if (sponge_squeeze(sp, key, key_bits) != CONSTR_SUCCESS) {
		explicit_bzero(key, (key_bits + 7) / 8);
		goto squeeze_fail;
	}

	ret = 0;

squeeze_fail:
	explicit_bzero(kdf_buf, KDF_RATE / 8);
absorb_fail:
	sponge_free(sp);
sponge_fail:
	keccakPad_10_1_free(p);
pad_fail:
	keccakF_1600_free(f);
permutation_fail:

	return ret;
}
