#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakF-1600.h"
#include "KeccakPad_10_1.h"
#include "spongewrap.h"

#define DEF_KEY (unsigned char *) "asdfasdf"

#define BIT_OVERHEAD 3

#define T_LEN_MAX 32

#define B_LEN_MAX 32
#define B_PATTERN 0xFE

#define A_LEN_MAX 32
#define A_PATTERN 0x12

#define ERR_TOGGLE_BITS 0x10

struct cipherctx_t {
	permutation *f_enc;
	permutation *f_dec;
	pad *p;
	size_t rate;
	size_t block_size;
	unsigned char *key;
	size_t key_byte_len;
};

static struct cipherctx_t cipherctx;

static spongewrap *mkcipher(permutation *f, struct cipherctx_t *ctx)
{
	return spongewrap_init(f, ctx->p, ctx->rate, ctx->block_size, ctx->key,
			ctx->key_byte_len);
}

static int regenCipher(permutation **f, spongewrap **w, struct cipherctx_t *ctx)
{
	permutation *fn = keccakF_1600_init(ctx->rate);
	if (fn == NULL) {
		return 1;
	}
	spongewrap *wn = mkcipher(fn, ctx);
	if (wn == NULL) {
		keccakF_1600_free(fn);
		return 1;
	}

	spongewrap_free(*w);
	keccakF_1600_free(*f);
	*w = wn;
	*f = fn;

	return 0;
}

static int testRunner(struct cipherctx_t *ctx, int (*test)(spongewrap**, spongewrap**,
			struct cipherctx_t*))
{
	int ret = 1;

	ctx->f_enc = keccakF_1600_init(ctx->rate);
	if (ctx->f_enc == NULL) {
		goto f_enc_fail;
	}

	ctx->f_dec = keccakF_1600_init(ctx->rate);
	if (ctx->f_dec == NULL) {
		goto f_dec_fail;
	}

	spongewrap *w_enc = mkcipher(ctx->f_enc, ctx);
	if (w_enc == NULL) {
		goto enc_fail;
	}

	spongewrap *w_dec = mkcipher(ctx->f_dec, ctx);
	if (w_dec == NULL) {
		goto dec_fail;
	}


	ret = test(&w_enc, &w_dec, ctx);

	spongewrap_free(w_dec);
dec_fail:
	spongewrap_free(w_enc);
enc_fail:
	keccakF_1600_free(ctx->f_dec);
f_dec_fail:
	keccakF_1600_free(ctx->f_enc);
f_enc_fail:

	return ret;
}

static int testInvalid_tag(spongewrap **w_enc, spongewrap **w_dec, struct cipherctx_t *ctx)
{
	unsigned char a[A_LEN_MAX];
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(a, A_PATTERN, A_LEN_MAX);
	memset(b, B_PATTERN, B_LEN_MAX);

	size_t err_idx;
	for (err_idx = 0; err_idx < T_LEN_MAX; err_idx++) {
		if (spongewrap_wrap(*w_enc, a, A_LEN_MAX, b, B_LEN_MAX, c, t,
					T_LEN_MAX) != 0) {
			return 1;
		}

		t[err_idx] ^= ERR_TOGGLE_BITS;

		if (spongewrap_unwrap(*w_dec, a, A_LEN_MAX, c, B_LEN_MAX, t, T_LEN_MAX,
					d) == 0) {
			return 1;
		}

		size_t i;
		for (i = 0; i < B_LEN_MAX; i++) {
			if (d[i] != 0) {
				return 1;
			}
		}


		if (regenCipher(&(ctx->f_enc), w_enc, ctx) != 0) {
			return 1;
		}

		if (regenCipher(&(ctx->f_dec), w_dec, ctx) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testInvalid_a(spongewrap **w_enc, spongewrap **w_dec, struct cipherctx_t *ctx)
{
	unsigned char a[A_LEN_MAX];
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(b, B_PATTERN, B_LEN_MAX);

	size_t err_idx;
	for (err_idx = 0; err_idx < A_LEN_MAX; err_idx++) {
		memset(a, A_PATTERN, A_LEN_MAX);

		if (spongewrap_wrap(*w_enc, a, A_LEN_MAX, b, B_LEN_MAX, c, t,
					T_LEN_MAX) != 0) {
			return 1;
		}

		a[err_idx] ^= ERR_TOGGLE_BITS;

		if (spongewrap_unwrap(*w_dec, a, A_LEN_MAX, c, B_LEN_MAX, t, T_LEN_MAX,
					d) == 0) {
			return 1;
		}

		size_t i;
		for (i = 0; i < B_LEN_MAX; i++) {
			if (d[i] != 0) {
				return 1;
			}
		}

		if (regenCipher(&(ctx->f_enc), w_enc, ctx) != 0) {
			return 1;
		}

		if (regenCipher(&(ctx->f_dec), w_dec, ctx) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testInvalid_c(spongewrap **w_enc, spongewrap **w_dec, struct cipherctx_t *ctx)
{
	unsigned char a[A_LEN_MAX];
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(a, A_PATTERN, A_LEN_MAX);
	memset(b, B_PATTERN, B_LEN_MAX);

	size_t err_idx;
	for (err_idx = 0; err_idx < B_LEN_MAX; err_idx++) {

		if (spongewrap_wrap(*w_enc, a, A_LEN_MAX, b, B_LEN_MAX, c, t,
					T_LEN_MAX) != 0) {
			return 1;
		}

		c[err_idx] ^= ERR_TOGGLE_BITS;

		if (spongewrap_unwrap(*w_dec, a, A_LEN_MAX, c, B_LEN_MAX, t, T_LEN_MAX,
					d) == 0) {
			return 1;
		}

		size_t i;
		for (i = 0; i < B_LEN_MAX; i++) {
			if (d[i] != 0) {
				return 1;
			}
		}

		if (regenCipher(&(ctx->f_enc), w_enc, ctx) != 0) {
			return 1;
		}

		if (regenCipher(&(ctx->f_dec), w_dec, ctx) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testEmpty_a_b(spongewrap **w_enc, spongewrap **w_dec, struct cipherctx_t *ctx)
{
	unsigned char t[T_LEN_MAX];

	size_t t_len;
	for (t_len = 0; t_len <= T_LEN_MAX; t_len++) {
		if (spongewrap_wrap(*w_enc, NULL, 0, NULL, 0, NULL, t, t_len) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(*w_dec, NULL, 0, NULL, 0, t, t_len, NULL) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testEncDec_empty_a(spongewrap **w_enc, spongewrap **w_dec,
		struct cipherctx_t *ctx)
{
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(b, B_PATTERN, B_LEN_MAX);

	size_t b_len;
	for (b_len = 0; b_len <= B_LEN_MAX; b_len++) {
		if (spongewrap_wrap(*w_enc, NULL, 0, b, b_len, c, t, T_LEN_MAX) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(*w_dec, NULL, 0, c, b_len, t, T_LEN_MAX, d) != 0) {
			return 1;
		}

		if (memcmp(b, d, b_len) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testEncDec_empty_b(spongewrap **w_enc, spongewrap **w_dec,
		struct cipherctx_t *ctx)
{
	unsigned char a[A_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(a, A_PATTERN, A_LEN_MAX);

	size_t a_len;
	for (a_len = 0; a_len <= A_LEN_MAX; a_len++) {
		if (spongewrap_wrap(*w_enc, a, a_len, NULL, 0, NULL, t, T_LEN_MAX) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(*w_dec, a, a_len, NULL, 0, t, T_LEN_MAX,
					NULL) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testEncDec(spongewrap **w_enc, spongewrap **w_dec, struct cipherctx_t *ctx)
{
	unsigned char a[A_LEN_MAX];
	unsigned char b[B_LEN_MAX];
	unsigned char c[B_LEN_MAX];
	unsigned char d[B_LEN_MAX];
	unsigned char t[T_LEN_MAX];

	memset(a, A_PATTERN, A_LEN_MAX);
	memset(b, B_PATTERN, B_LEN_MAX);

	size_t a_len;
	for (a_len = 0; a_len <= A_LEN_MAX; a_len++) {
		if (spongewrap_wrap(*w_enc, a, a_len, b, B_LEN_MAX, c, t,
					T_LEN_MAX) != 0) {
			return 1;
		}

		if (spongewrap_unwrap(*w_dec, a, a_len, c, B_LEN_MAX, t, T_LEN_MAX,
					d) != 0) {
			return 1;
		}

		if (memcmp(b, d, B_LEN_MAX) != 0) {
			return 1;
		}
	}

	return 0;
}

static int testSpongeWrap_internal(size_t rate, size_t block_size,
		unsigned char *key, const size_t key_byte_len)
{
	int ret = 1;

	pad *p = keccakPad_10_1_init(rate);
	if (p == NULL) {
		goto pad_fail;
	}

	cipherctx.p = p;
	cipherctx.rate = rate;
	cipherctx.block_size = block_size;
	cipherctx.key = key;
	cipherctx.key_byte_len = key_byte_len;

	if (testRunner(&cipherctx, testEmpty_a_b) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testEncDec_empty_a) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testEncDec_empty_b) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testEncDec) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testInvalid_tag) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testInvalid_a) != 0) {
		goto fail;
	}

	if (testRunner(&cipherctx, testInvalid_c) != 0) {
		goto fail;
	}

	ret = 0;

fail:
	keccakPad_10_1_free(p);
pad_fail:

	return ret;
}

int testSpongeWrap(void)
{
	size_t block_sizes[] = { 4, 8, 16, 32, 64 };
	size_t rates[] = { 1024, 1152, 1088, 832, 576 };

	size_t block_size;
	size_t rate;

	size_t block_size_idx;
	size_t rate_idx;
	for (block_size_idx = 0; block_size_idx < sizeof(block_sizes) /
			sizeof(block_sizes[0]); block_size_idx++) {
		for (rate_idx = 0; rate_idx < sizeof(rates) / sizeof(rates[0]);
				rate_idx++) {
			rate = rates[rate_idx];
			block_size = block_sizes[block_size_idx];

			if (block_size * 8 + BIT_OVERHEAD > rate) {
				continue;
			}

			if (testSpongeWrap_internal(rate, block_size, DEF_KEY,
						sizeof(DEF_KEY)) != 0) {
				return 1;
			}
		}

		if (testSpongeWrap_internal(block_size * 8 + BIT_OVERHEAD, block_size,
					DEF_KEY, sizeof(DEF_KEY)) != 0) {
			return 1;
		}
	}

	return 0;
}
