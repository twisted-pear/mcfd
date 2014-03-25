#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakF-1600.h"
#include "KeccakPad_10_1.h"
#include "spongewrap.h"

static int testEmpty(spongewrap *w_enc, spongewrap *w_dec)
{
	if (spongewrap_wrap(w_enc, NULL, 0, NULL, 0, NULL, NULL, 0) != 0) {
		return 1;
	}

	if (spongewrap_unwrap(w_dec, NULL, 0, NULL, 0, NULL, 0, NULL) != 0) {
		return 1;
	}

	return 0;
}

static int testEmpty_a_b(spongewrap *w_enc, spongewrap *w_dec)
{
	unsigned char t[2];

	if (spongewrap_wrap(w_enc, NULL, 0, NULL, 0, NULL, t, 2) != 0) {
		return 1;
	}

	if (spongewrap_unwrap(w_dec, NULL, 0, NULL, 0, t, 2, NULL) != 0) {
		return 1;
	}

	return 0;
}

static int testSpongeWrap_internal(size_t rate, size_t block_size,
		const unsigned char *key, const size_t key_byte_len)
{
	int ret = 1;

	permutation *f = keccakF_1600_init();
	if (f == NULL) {
		goto f_fail;
	}

	pad *p = keccakPad_10_1_init(rate);
	if (p == NULL) {
		goto pad_fail;
	}

	spongewrap *w_enc = spongewrap_init(f, p, rate, block_size, key, key_byte_len);
	if (w_enc == NULL) {
		goto enc_fail;
	}

	spongewrap *w_dec = spongewrap_init(f, p, rate, block_size, key, key_byte_len);
	if (w_dec == NULL) {
		goto dec_fail;
	}

	if (testEmpty(w_enc, w_dec) != 0) {
		goto fail;
	}

	if (testEmpty_a_b(w_enc, w_dec) != 0) {
		goto fail;
	}

	ret = 0;

fail:
	spongewrap_free(w_dec);
dec_fail:
	spongewrap_free(w_enc);
enc_fail:
	keccakPad_10_1_free(p);
pad_fail:
	keccakF_1600_free(f);

f_fail:
	return ret;
}

int testSpongeWrap(void)
{
	return testSpongeWrap_internal(11, 1, (unsigned char *) "a", 1);
}
