#include <stdlib.h>
#include <string.h>

#include <pad.h>
#include <permutation.h>
#include <spongewrap.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_WIDTH 1600
#define CREATE_RATE 1024
#define CREATE_MIN_RATE 2
#define CREATE_BLOCK_SIZE (1016 / 8) // block size is in byte
#define CREATE_MAX_ALLOC_SIZE (CREATE_RATE * 2)
#define CREATE_MAX_ALLOCS 10
#define CREATE_KEY_SIZE (256 / 8) // key length is in byte

#define GET_PATTERN 0x06

#define KEYBUF_SIZE (2048 / 8) // key length is in byte
#define KEYBUF_PATTERN 0xAA

#define A_SIZE (4096 / 8) // in byte
#define A_PATTERN 0xA0

#define B_SIZE (4096 / 8) // in byte
#define B_PATTERN 0xB0

#define C_SIZE (4096 / 8) // in byte
#define C_PATTERN 0xC0

#define T_SIZE (4096 / 8) // in byte
#define T_PATTERN 0x70

static int spongewrap_order = 0;
static spongewrap *w = NULL;
static size_t expected_block_size = 0;

static int spongewrap_f(permutation *p __attribute__((unused)))
{
	assert_false(1);

	return -1;
}

static int expected_frame_bit(void)
{
	return mock_type(int);
}

static int spongewrap_xor(permutation *p, const size_t start_bit_idx,
		const unsigned char *input, const size_t input_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(input);
	check_expected(input_bit_len);

	assert_in_range(spongewrap_order, 0, 2);

	if (spongewrap_order == 0) {
		assert_int_equal(start_bit_idx, 0);
		assert_in_range(input_bit_len, 0, (expected_block_size * 8) -
				start_bit_idx);
	} else if (spongewrap_order == 1) {
		assert_in_range(start_bit_idx, 0, (expected_block_size * 8));
		assert_int_equal(input_bit_len, 1);
		assert_int_equal(input[0], expected_frame_bit() << 7);
	} else {
		assert_true(0);
	}

	spongewrap_order++;

	return mock_type(int);
}

static int spongewrap_get(permutation *p, const size_t start_bit_idx,
		unsigned char *output, const size_t output_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(output);
	check_expected(output_bit_len);

	assert_int_equal(spongewrap_order, 3);

	assert_int_equal(start_bit_idx, 0);
	assert_in_range(output_bit_len, 0, (expected_block_size * 8) - start_bit_idx);

	spongewrap_order = 0;

	memset(output, GET_PATTERN, (output_bit_len + 7) / 8);

	return mock_type(int);
}

static int spongewrap_pf(pad *p, permutation *f, const size_t remaining_bits)
{
	check_expected(p);
	check_expected(f);
	check_expected(remaining_bits);

	assert_int_equal(spongewrap_order, 2);

	assert_in_range(remaining_bits, 0, (expected_block_size * 8) + 1);

	spongewrap_order++;

	return mock_type(int);
}

static permutation *f = NULL;
static pad *p = NULL;
static unsigned char *keybuf = NULL;

static void spongewrap_init_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->f = spongewrap_f;
	f->xor = spongewrap_xor;
	f->get = spongewrap_get;
	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->pf = spongewrap_pf;
	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;

	expected_block_size = CREATE_BLOCK_SIZE;

	keybuf = calloc(KEYBUF_SIZE, 1);
	assert_non_null(keybuf);
	memset(keybuf, KEYBUF_PATTERN, KEYBUF_SIZE);
}

static void spongewrap_init_teardown(void **state __attribute__((unused)))
{
	spongewrap_order = 0;

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

	free(f);
	free(p);
	free(keybuf);
}

static void spongewrap_init_f_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(NULL, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_p_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, NULL, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_key_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, NULL,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_zero(void **state __attribute__((unused)))
{
	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongewrap_init(f, p, 0, CREATE_BLOCK_SIZE, keybuf, CREATE_KEY_SIZE));
}

static void spongewrap_init_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_klen_zero(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf, 0));
}

static void spongewrap_init_bs_zero(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, 0, keybuf, CREATE_KEY_SIZE));
	expected_block_size = 0;
}

static void spongewrap_init_rate_zero_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongewrap_init(f, p, 0, CREATE_BLOCK_SIZE, keybuf, CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_gt_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH + 8;

	assert_null(spongewrap_init(f, p, CREATE_WIDTH + 8, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_eq_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH;

	assert_null(spongewrap_init(f, p, CREATE_WIDTH, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_ne_prate(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE + 8, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE + 1;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));
}

static void spongewrap_init_bs_gt_maxbs(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE,
				(CREATE_RATE - CREATE_MIN_RATE + 7) / 8,
				keybuf, CREATE_KEY_SIZE));
	expected_block_size = (CREATE_RATE - CREATE_MIN_RATE + 7) / 8;
}

#define __DUPLEX_CALL_ANY_OUT ((void *) -1)
static void duplex_call_success(const unsigned char* in, const size_t in_byte_len,
		const unsigned char *out, const size_t out_byte_len, const int frame_bit)
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, in);
	expect_value(spongewrap_xor, input_bit_len, in_byte_len * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, in_byte_len * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_pf, p, p);
	expect_value(spongewrap_pf, f, f);
	expect_value(spongewrap_pf, remaining_bits, (in_byte_len * 8) + 1);
	will_return(spongewrap_pf, 0);

	expect_value(spongewrap_get, p, f);
	expect_value(spongewrap_get, start_bit_idx, 0);
	if (out == __DUPLEX_CALL_ANY_OUT) {
		expect_any(spongewrap_get, output);
	} else {
		expect_value(spongewrap_get, output, out);
	}
	expect_value(spongewrap_get, output_bit_len, out_byte_len * 8);
	will_return(spongewrap_get, 0);

	will_return(expected_frame_bit, frame_bit);
}

static void spongewrap_init_success(const size_t block_size, const size_t key_byte_len)
{
	unsigned char *key_cur = keybuf;
	size_t key_remaining = key_byte_len;

	for (;;) {
		if (key_remaining > block_size) {
			duplex_call_success(key_cur, block_size, NULL, 0, 1);
		} else {
			duplex_call_success(key_cur, key_remaining, NULL, 0, 0);
			break;
		}

		key_cur += block_size;
		key_remaining -= block_size;
	}
}

static void spongewrap_init_klen_gt_bs(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE + 1);

	__activate_wrap_alloc = 1;

	w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
			CREATE_BLOCK_SIZE + 1);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongewrap_free(w);
}

static void spongewrap_init_rate_odd(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	size_t rate;
	for (rate = CREATE_RATE + 1; rate < CREATE_RATE + 8; rate++) {
		p->rate = rate;

		spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

		__activate_wrap_alloc = 1;

		w = spongewrap_init(f, p, rate, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE);

		__activate_wrap_alloc = 0;

		assert_non_null(w);

		assert_true(w->f == f);
		assert_true(w->p == p);
		assert_true(w->rate == rate);
		assert_true(w->block_size == CREATE_BLOCK_SIZE);

		size_t i;
		for (i = 0; i < KEYBUF_SIZE; i++) {
			assert_int_equal(keybuf[i], KEYBUF_PATTERN);
		}

		spongewrap_free(w);
	}
}

static void spongewrap_init_width_odd(void **state __attribute__((unused)))
{
	size_t width;
	for (width = CREATE_WIDTH + 1; width < CREATE_WIDTH + 7; width++) {
		f->width = width;
		assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
					CREATE_KEY_SIZE));

		size_t i;
		for (i = 0; i < KEYBUF_SIZE; i++) {
			assert_int_equal(keybuf[i], KEYBUF_PATTERN);
		}
	}
}

static void spongewrap_init_noalloc(void **state __attribute__((unused)))
{
	/* spongewrap_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	spongewrap *w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
			CREATE_KEY_SIZE);

	__activate_wrap_alloc = 0;

	assert_null(w);
}

static void spongewrap_init_alloc_limited(void **state __attribute__((unused)))
{
	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	w = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE,
				keybuf, CREATE_KEY_SIZE);
		if (w != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongewrap_free(w);
}

static void spongewrap_init_normal(void **state __attribute__((unused)))
{
	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
			CREATE_KEY_SIZE);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongewrap_free(w);
}

static void spongewrap_init_rate_max(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH - 1;

	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	w = spongewrap_init(f, p, CREATE_WIDTH - 1, CREATE_BLOCK_SIZE, keybuf,
			CREATE_KEY_SIZE);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_WIDTH - 1);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongewrap_free(w);
}

static void spongewrap_init_bs_max(void **state __attribute__((unused)))
{
	spongewrap_init_success((CREATE_RATE - CREATE_MIN_RATE - 1) / 8, CREATE_KEY_SIZE);

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	w = spongewrap_init(f, p, CREATE_RATE, (CREATE_RATE - CREATE_MIN_RATE - 1) / 8,
			keybuf, CREATE_KEY_SIZE);

	__activate_wrap_alloc = 0;


	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == (CREATE_RATE - CREATE_MIN_RATE - 1) / 8);

	expected_block_size = (CREATE_RATE - CREATE_MIN_RATE - 1) / 8;

	spongewrap_free(w);
}

static unsigned char *a;
static unsigned char *b;
static unsigned char *c;
static unsigned char *t;

static void spongewrap_wrap_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->f = spongewrap_f;
	f->xor = spongewrap_xor;
	f->get = spongewrap_get;
	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->pf = spongewrap_pf;
	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;

	expected_block_size = CREATE_BLOCK_SIZE;

	keybuf = calloc(KEYBUF_SIZE, 1);
	assert_non_null(keybuf);
	memset(keybuf, KEYBUF_PATTERN, KEYBUF_SIZE);

	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

	w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
			CREATE_KEY_SIZE);
	assert_non_null(w);

	free(keybuf);

	a = calloc(A_SIZE, 1);
	assert_non_null(a);
	memset(a, A_PATTERN, A_SIZE);

	b = calloc(B_SIZE, 1);
	assert_non_null(b);
	memset(b, B_PATTERN, B_SIZE);

	c = calloc(C_SIZE, 1);
	assert_non_null(c);
	memset(c, C_PATTERN, C_SIZE);

	t = calloc(T_SIZE, 1);
	assert_non_null(t);
	memset(t, T_PATTERN, T_SIZE);
}

static void spongewrap_wrap_teardown(void **state __attribute__((unused)))
{
	spongewrap_order = 0;

	spongewrap_free(w);
	free(f);
	free(p);

	size_t i;
	for (i = 0; i < A_SIZE; i++) {
		assert_int_equal(a[i], A_PATTERN);
	}
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}

	free(a);
	free(b);
	free(c);
	free(t);
}

static void spongewrap_wrap_success(const size_t block_size, const size_t a_byte_len,
		const size_t b_byte_len, const size_t t_byte_len, unsigned char *a,
		unsigned char *b, unsigned char *c, unsigned char *t)
{
	unsigned char *a_cur = a;
	size_t a_remaining = a_byte_len;
	unsigned char *b_cur = b;
	size_t b_remaining = b_byte_len;
	unsigned char *c_cur = c;
	size_t c_remaining = b_byte_len;
	unsigned char *t_cur = t;
	size_t t_remaining = t_byte_len;

	for (;;) {
		if (a_remaining > block_size) {
			duplex_call_success(a_cur, block_size, NULL, 0, 0);
		} else {
			size_t b_next = (b_remaining > block_size) ? block_size :
				b_remaining;
			duplex_call_success(a_cur, a_remaining, c_cur, b_next, 1);
			c_remaining -= b_next;
			c_cur += b_next;
			break;
		}

		a_cur += block_size;
		a_remaining -= block_size;
	}

	for (;;) {
		if (b_remaining > block_size ) {
			size_t c_next = (c_remaining > block_size) ? block_size :
				c_remaining;
			duplex_call_success(b_cur, block_size, c_cur, c_next, 1);
			c_remaining -= c_next;
			c_cur += c_next;
		} else {
			size_t t_next = (t_remaining > block_size) ? block_size :
				t_remaining;
			duplex_call_success(b_cur, b_remaining, t_cur, t_next, 0);
			t_remaining -= t_next;
			t_cur += t_next;
			break;
		}

		b_cur += block_size;
		b_remaining -= block_size;
	}

	assert_int_equal(c_remaining, 0);

	if (t_remaining == 0) {
		return;
	}

	for (;;) {
		if (t_remaining > block_size) {
			duplex_call_success(NULL, 0, t_cur, block_size, 0);
		} else {
			duplex_call_success(NULL, 0, t_cur, t_remaining, 0);
			break;
		}

		t_cur += block_size;
		t_remaining -= block_size;
	}
}

static void spongewrap_wrap_w_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(NULL, a, A_SIZE, b, B_SIZE, c, t, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_a_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(w, NULL, A_SIZE, b, B_SIZE, c, t, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_a_null_alen_zero(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, 0, B_SIZE, T_SIZE, NULL, b, c, t);

	assert_int_equal(spongewrap_wrap(w, NULL, 0, b, B_SIZE, c, t, T_SIZE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_b_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, NULL, B_SIZE, c, t, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_b_null_blen_zero(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, NULL, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, NULL, 0, c, t, T_SIZE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_c_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, NULL, t, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_c_null_blen_zero(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, b, NULL, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, 0, NULL, t, T_SIZE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_t_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, NULL, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_t_null_tlen_zero(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, 0, a, b, c, NULL);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, NULL, 0),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_b_eq_c(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, b, t, T_SIZE),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_b_eq_c_null(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, NULL, NULL, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, NULL, 0, NULL, t, T_SIZE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_xor_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 1);

	expect_assert_failure(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE));

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}

	spongewrap_order = 0;

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE));

	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_pf_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_pf, p, p);
	expect_value(spongewrap_pf, f, f);
	expect_value(spongewrap_pf, remaining_bits, (CREATE_BLOCK_SIZE * 8) + 1);
	will_return(spongewrap_pf, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE));

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_get_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_pf, p, p);
	expect_value(spongewrap_pf, f, f);
	expect_value(spongewrap_pf, remaining_bits, (CREATE_BLOCK_SIZE * 8) + 1);
	will_return(spongewrap_pf, 0);

	expect_value(spongewrap_get, p, f);
	expect_value(spongewrap_get, start_bit_idx, 0);
	expect_value(spongewrap_get, output, NULL);
	expect_value(spongewrap_get, output_bit_len, 0);
	will_return(spongewrap_get, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE));

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_noalloc(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, T_SIZE, a, b, c, t);

	/* spongewrap_wrap must not allocate any memory */

	__activate_wrap_alloc = 1;

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE),
			CONSTR_SUCCESS);

	__activate_wrap_alloc = 0;

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_normal(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_alen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE - 1, B_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, CREATE_BLOCK_SIZE - 1, b, B_SIZE, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_alen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE, B_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, CREATE_BLOCK_SIZE, b, B_SIZE, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_alen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE + 1, B_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, CREATE_BLOCK_SIZE + 1, b, B_SIZE, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}

}

static void spongewrap_wrap_blen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE - 1, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, CREATE_BLOCK_SIZE - 1, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE - 1; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE - 1; i < C_SIZE - (CREATE_BLOCK_SIZE - 1); i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_blen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, CREATE_BLOCK_SIZE, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE; i < C_SIZE - CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_blen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE + 1, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, CREATE_BLOCK_SIZE + 1, c, t,
				T_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE + 1; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE + 1; i < C_SIZE - (CREATE_BLOCK_SIZE + 1); i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
}

static void spongewrap_wrap_tlen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, CREATE_BLOCK_SIZE - 1,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t,
				CREATE_BLOCK_SIZE - 1), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < CREATE_BLOCK_SIZE - 1; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE - 1; i < T_SIZE - (CREATE_BLOCK_SIZE - 1); i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_tlen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, CREATE_BLOCK_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t,
				CREATE_BLOCK_SIZE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE; i < T_SIZE - CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_wrap_tlen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_wrap_success(CREATE_BLOCK_SIZE, A_SIZE, B_SIZE, CREATE_BLOCK_SIZE + 1,
			a, b, c, t);

	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t,
				CREATE_BLOCK_SIZE + 1), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], B_PATTERN ^ GET_PATTERN);
	}
	for (i = 0; i < CREATE_BLOCK_SIZE + 1; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE + 1; i < T_SIZE - (CREATE_BLOCK_SIZE + 1); i++) {
		assert_int_equal(t[i], T_PATTERN);
	}
}

static void spongewrap_unwrap_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->f = spongewrap_f;
	f->xor = spongewrap_xor;
	f->get = spongewrap_get;
	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->pf = spongewrap_pf;
	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;

	expected_block_size = CREATE_BLOCK_SIZE;

	keybuf = calloc(KEYBUF_SIZE, 1);
	assert_non_null(keybuf);
	memset(keybuf, KEYBUF_PATTERN, KEYBUF_SIZE);

	spongewrap_init_success(CREATE_BLOCK_SIZE, CREATE_KEY_SIZE);

	w = spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
			CREATE_KEY_SIZE);
	assert_non_null(w);

	free(keybuf);

	a = calloc(A_SIZE, 1);
	assert_non_null(a);
	memset(a, A_PATTERN, A_SIZE);

	b = calloc(B_SIZE, 1);
	assert_non_null(b);
	memset(b, B_PATTERN, B_SIZE);

	c = calloc(C_SIZE, 1);
	assert_non_null(c);
	memset(c, C_PATTERN, C_SIZE);

	t = calloc(T_SIZE, 1);
	assert_non_null(t);
	memset(t, GET_PATTERN, T_SIZE);
}

static void spongewrap_unwrap_teardown(void **state __attribute__((unused)))
{
	spongewrap_order = 0;

	spongewrap_free(w);
	free(f);
	free(p);

	size_t i;
	for (i = 0; i < A_SIZE; i++) {
		assert_int_equal(a[i], A_PATTERN);
	}
	for (i = 0; i < C_SIZE; i++) {
		assert_int_equal(c[i], C_PATTERN);
	}
	for (i = 0; i < T_SIZE; i++) {
		assert_int_equal(t[i], GET_PATTERN);
	}

	free(a);
	free(b);
	free(c);
	free(t);
}

static void spongewrap_unwrap_success(const size_t block_size, const size_t a_byte_len,
		const size_t c_byte_len, const size_t t_byte_len, unsigned char *a,
		unsigned char *b, unsigned char *c, unsigned char *t)
{
	unsigned char *a_cur = a;
	size_t a_remaining = a_byte_len;
	unsigned char *b_cur = b;
	size_t b_remaining = c_byte_len;
	unsigned char *c_cur = c;
	size_t c_remaining = c_byte_len;
	unsigned char *t_cur = t;
	size_t t_remaining = t_byte_len;

	for (;;) {
		if (a_remaining > block_size) {
			duplex_call_success(a_cur, block_size, NULL, 0, 0);
		} else {
			size_t c_next = (c_remaining > block_size) ? block_size :
				c_remaining;
			duplex_call_success(a_cur, a_remaining, b_cur, c_next, 1);
			c_remaining -= c_next;
			c_cur += c_next;
			break;
		}

		a_cur += block_size;
		a_remaining -= block_size;
	}

	for (;;) {
		if (b_remaining > block_size ) {
			size_t c_next = (c_remaining > block_size) ? block_size :
				c_remaining;
			duplex_call_success(b_cur, block_size, b_cur + block_size, c_next,
					1);
			c_remaining -= c_next;
			c_cur += c_next;
		} else {
			size_t t_next = (t_remaining > block_size) ? block_size :
				t_remaining;
			duplex_call_success(b_cur, b_remaining, __DUPLEX_CALL_ANY_OUT,
					t_next, 0);
			t_remaining -= t_next;
			t_cur += t_next;
			break;
		}

		b_cur += block_size;
		b_remaining -= block_size;
	}

	assert_int_equal(c_remaining, 0);

	if (t_remaining == 0) {
		return;
	}

	for (;;) {
		if (t_remaining > block_size) {
			duplex_call_success(NULL, 0, __DUPLEX_CALL_ANY_OUT, block_size,
					0);
		} else {
			duplex_call_success(NULL, 0, __DUPLEX_CALL_ANY_OUT, t_remaining,
					0);
			break;
		}

		t_cur += block_size;
		t_remaining -= block_size;
	}
}

static void spongewrap_unwrap_w_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(NULL, a, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_a_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(w, NULL, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_a_null_alen_zero(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, 0, C_SIZE, T_SIZE, NULL, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, NULL, 0, c, C_SIZE, t, T_SIZE, b),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_b_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, NULL),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_b_null_clen_zero(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, NULL, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, 0, t, T_SIZE, NULL),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_c_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, NULL, C_SIZE, t, T_SIZE, b),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_c_null_clen_zero(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, b, NULL, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, NULL, 0, t, T_SIZE, b),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_t_null(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, NULL, T_SIZE, b),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_t_null_tlen_zero(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE, 0, a, b, c, NULL);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, NULL, 0, b),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_b_eq_c(void **state __attribute__((unused)))
{
	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, c),
			CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_b_eq_c_null(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, 0, T_SIZE, a, NULL, NULL, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, NULL, 0, t, T_SIZE, NULL),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_xor_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 1);

	expect_assert_failure(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b));

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}

	spongewrap_order = 0;

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b));

	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_pf_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_pf, p, p);
	expect_value(spongewrap_pf, f, f);
	expect_value(spongewrap_pf, remaining_bits, (CREATE_BLOCK_SIZE * 8) + 1);
	will_return(spongewrap_pf, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b));

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_get_fail(void **state __attribute__((unused)))
{
	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, 0);
	expect_value(spongewrap_xor, input, a);
	expect_value(spongewrap_xor, input_bit_len, CREATE_BLOCK_SIZE * 8);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_xor, p, f);
	expect_value(spongewrap_xor, start_bit_idx, CREATE_BLOCK_SIZE * 8);
	expect_any(spongewrap_xor, input);
	expect_value(spongewrap_xor, input_bit_len, 1);
	will_return(spongewrap_xor, 0);

	expect_value(spongewrap_pf, p, p);
	expect_value(spongewrap_pf, f, f);
	expect_value(spongewrap_pf, remaining_bits, (CREATE_BLOCK_SIZE * 8) + 1);
	will_return(spongewrap_pf, 0);

	expect_value(spongewrap_get, p, f);
	expect_value(spongewrap_get, start_bit_idx, 0);
	expect_value(spongewrap_get, output, NULL);
	expect_value(spongewrap_get, output_bit_len, 0);
	will_return(spongewrap_get, 1);

	will_return(expected_frame_bit, 0);

	expect_assert_failure(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b));

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_noalloc(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE, T_SIZE, a, b, c, t);

	/* spongewrap_unwrap must not allocate any memory */

	__activate_wrap_alloc = 1;

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_SUCCESS);

	__activate_wrap_alloc = 0;

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_normal(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE, T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_alen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE - 1, C_SIZE,
			T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, CREATE_BLOCK_SIZE - 1, c, C_SIZE, t,
				T_SIZE, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_alen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE, C_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, CREATE_BLOCK_SIZE, c, C_SIZE, t, T_SIZE,
				b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_alen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, CREATE_BLOCK_SIZE + 1, C_SIZE,
			T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, CREATE_BLOCK_SIZE + 1, c, C_SIZE, t,
				T_SIZE, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_clen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE - 1,
			T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, CREATE_BLOCK_SIZE - 1, t,
				T_SIZE, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE - 1; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE - 1; i < B_SIZE - (CREATE_BLOCK_SIZE - 1); i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_clen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE, T_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, CREATE_BLOCK_SIZE, t, T_SIZE,
				b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE; i < B_SIZE - CREATE_BLOCK_SIZE; i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_clen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, CREATE_BLOCK_SIZE + 1,
			T_SIZE, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, CREATE_BLOCK_SIZE + 1, t,
				T_SIZE, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_BLOCK_SIZE + 1; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
	for (i = CREATE_BLOCK_SIZE + 1; i < B_SIZE - (CREATE_BLOCK_SIZE + 1); i++) {
		assert_int_equal(b[i], B_PATTERN);
	}
}

static void spongewrap_unwrap_tlen_lt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE,
			CREATE_BLOCK_SIZE - 1, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t,
				CREATE_BLOCK_SIZE - 1, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_tlen_eq_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE, CREATE_BLOCK_SIZE,
			a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, CREATE_BLOCK_SIZE,
				b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_tlen_gt_bs(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE,
			CREATE_BLOCK_SIZE + 1, a, b, c, t);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t,
				CREATE_BLOCK_SIZE + 1, b), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], C_PATTERN ^ GET_PATTERN);
	}
}

static void spongewrap_unwrap_t_invalid(void **state __attribute__((unused)))
{
	spongewrap_unwrap_success(CREATE_BLOCK_SIZE, A_SIZE, C_SIZE, T_SIZE, a, b, c, t);

	memset(t, T_PATTERN, T_SIZE);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_FATAL);

	memset(t, GET_PATTERN, T_SIZE);

	assert_int_equal(spongewrap_unwrap(w, a, A_SIZE, c, C_SIZE, t, T_SIZE, b),
			CONSTR_FATAL);
	assert_int_equal(spongewrap_wrap(w, a, A_SIZE, b, B_SIZE, c, t, T_SIZE),
			CONSTR_FATAL);

	size_t i;
	for (i = 0; i < B_SIZE; i++) {
		assert_int_equal(b[i], 0);
	}
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest spongewrap_init_tests[] = {
		unit_test_setup_teardown(spongewrap_init_f_null, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_p_null, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_key_null, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_zero, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_width_zero,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_klen_zero, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_bs_zero, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_zero_width_zero,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_gt_width,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_eq_width,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_ne_prate,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_lt_minrate,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_eq_minrate,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_bs_gt_maxbs,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_klen_gt_bs,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_odd, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_width_odd, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_noalloc, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_alloc_limited,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_normal, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_rate_max, spongewrap_init_setup,
				spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_bs_max, spongewrap_init_setup,
				spongewrap_init_teardown)
	};

	fprintf(stderr, "spongewrap_init:\n");
	res |= run_tests(spongewrap_init_tests);
	fprintf(stderr, "\n");

	const UnitTest spongewrap_wrap_tests[] = {
		unit_test_setup_teardown(spongewrap_wrap_w_null, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_a_null, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_a_null_alen_zero,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_b_null, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_b_null_blen_zero,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_c_null, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_c_null_blen_zero,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_t_null, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_t_null_tlen_zero,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_b_eq_c, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_b_eq_c_null,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_xor_fail,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_pf_fail,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_get_fail,
				spongewrap_wrap_setup, spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_noalloc, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_normal, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_alen_lt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_alen_eq_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_alen_gt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_blen_lt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_blen_eq_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_blen_gt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_tlen_lt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_tlen_eq_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown),
		unit_test_setup_teardown(spongewrap_wrap_tlen_gt_bs, spongewrap_wrap_setup,
				spongewrap_wrap_teardown)
	};

	fprintf(stderr, "spongewrap_wrap:\n");
	res |= run_tests(spongewrap_wrap_tests);
	fprintf(stderr, "\n");

	const UnitTest spongewrap_unwrap_tests[] = {
		unit_test_setup_teardown(spongewrap_unwrap_w_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_a_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_a_null_alen_zero,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_b_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_b_null_clen_zero,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_c_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_c_null_clen_zero,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_t_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_t_null_tlen_zero,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_b_eq_c,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_b_eq_c_null,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_xor_fail,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_pf_fail,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_get_fail,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_noalloc,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_normal,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_alen_lt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_alen_eq_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_alen_gt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_clen_lt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_clen_eq_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_clen_gt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_tlen_lt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_tlen_eq_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_tlen_gt_bs,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown),
		unit_test_setup_teardown(spongewrap_unwrap_t_invalid,
				spongewrap_unwrap_setup, spongewrap_unwrap_teardown)
	};

	fprintf(stderr, "spongewrap_unwrap:\n");
	res |= run_tests(spongewrap_unwrap_tests);
	fprintf(stderr, "\n");

	return res;
}
