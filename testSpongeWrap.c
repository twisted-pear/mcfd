#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakF-1600.h"
#include "KeccakPad_10_1.h"
#include "spongewrap.h"

#define T_LEN_MAX 512

#define B_LEN_MAX 512
#define B_PATTERN 0xFE

static int testRunner(permutation *f, pad *p, size_t rate, size_t block_size,
		const unsigned char *key, const size_t key_byte_len,
		int (*test)(spongewrap*, spongewrap*))
{
	int ret = 1;

	spongewrap *w_enc = spongewrap_init(f, p, rate, block_size, key, key_byte_len);
	if (w_enc == NULL) {
		goto enc_fail;
	}

	spongewrap *w_dec = spongewrap_init(f, p, rate, block_size, key, key_byte_len);
	if (w_dec == NULL) {
		goto dec_fail;
	}


	ret = test(w_enc, w_dec);

	spongewrap_free(w_dec);
dec_fail:
	spongewrap_free(w_enc);
enc_fail:

	return ret;
}

static int testEmpty_a_b(spongewrap *w_enc, spongewrap *w_dec)
{
	unsigned char t[T_LEN_MAX];

	size_t t_len;
	for (t_len = 0; t_len <= T_LEN_MAX; t_len++) {
		if (spongewrap_wrap(w_enc, NULL, 0, NULL, 0, NULL, t, t_len) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(w_dec, NULL, 0, NULL, 0, t, t_len, NULL) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testEncDec_empty_a(spongewrap *w_enc, spongewrap *w_dec)
{
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(b, B_PATTERN, B_LEN_MAX);

	size_t b_len;
	for (b_len = 0; b_len <= B_LEN_MAX; b_len++) {
		if (spongewrap_wrap(w_enc, NULL, 0, b, b_len, c, t, T_LEN_MAX) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(w_dec, NULL, 0, c, b_len, t, T_LEN_MAX, d) != 0) {
			return 1;
		}

		if (memcmp(b, d, b_len) != 0) {
			return 1;
		}
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

	if (testRunner(f, p, rate, block_size, key, key_byte_len, testEmpty_a_b) != 0) {
		goto fail;
	}

	if (testRunner(f, p, rate, block_size, key, key_byte_len, testEncDec_empty_a) != 0) {
		goto fail;
	}

	ret = 0;

fail:
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
