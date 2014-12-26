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
#define CREATE_RATE 1027
#define CREATE_MIN_RATE 2
#define CREATE_BLOCK_SIZE (1024 / 8) // block size is in byte
#define CREATE_MAX_ALLOC_SIZE (CREATE_RATE * 2)
#define CREATE_MAX_ALLOCS 10
#define CREATE_KEY_SIZE (256 / 8) // key length is in byte

#define KEYBUF_SIZE (2048 / 8) // key length is in byte
#define KEYBUF_PATTERN 0xAA

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
	memset(keybuf, KEYBUF_PATTERN, KEYBUF_SIZE);

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
	free(keybuf);
}

static void spongewrap_init_f_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(NULL, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_p_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, NULL, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_key_null(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, NULL,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_zero(void **state __attribute__((unused)))
{
	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongewrap_init(f, p, 0, CREATE_BLOCK_SIZE, keybuf, CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_klen_zero(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf, 0));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_bs_zero(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE, 0, keybuf, CREATE_KEY_SIZE));
	expected_block_size = 0;

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_zero_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongewrap_init(f, p, 0, CREATE_BLOCK_SIZE, keybuf, CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_gt_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH + 8;

	assert_null(spongewrap_init(f, p, CREATE_WIDTH + 8, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_eq_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH;

	assert_null(spongewrap_init(f, p, CREATE_WIDTH, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_ne_prate(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE + 8, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE + 1;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE;

	assert_null(spongewrap_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE, keybuf,
				CREATE_KEY_SIZE));

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

static void spongewrap_init_bs_gt_maxbs(void **state __attribute__((unused)))
{
	assert_null(spongewrap_init(f, p, CREATE_RATE,
				(CREATE_RATE - CREATE_MIN_RATE + 7) / 8,
				keybuf, CREATE_KEY_SIZE));
	expected_block_size = (CREATE_RATE - CREATE_MIN_RATE + 7) / 8;

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}
}

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
	expect_value(spongewrap_get, output, out);
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

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

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

	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

	spongewrap_free(w);
}

static void spongewrap_init_xor_fail(void **state __attribute__((unused)))
{
}

static void spongewrap_init_pf_fail(void **state __attribute__((unused)))
{
}

static void spongewrap_init_get_fail(void **state __attribute__((unused)))
{
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

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

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

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

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

	size_t i;
	for (i = 0; i < KEYBUF_SIZE; i++) {
		assert_int_equal(keybuf[i], KEYBUF_PATTERN);
	}

	spongewrap_free(w);
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
		unit_test_setup_teardown(spongewrap_init_xor_fail,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_pf_fail,
				spongewrap_init_setup, spongewrap_init_teardown),
		unit_test_setup_teardown(spongewrap_init_get_fail,
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

	return res;
}
