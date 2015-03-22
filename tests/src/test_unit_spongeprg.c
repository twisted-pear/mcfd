#include <stdlib.h>
#include <string.h>

#include <pad.h>
#include <permutation.h>
#include <spongeprg.h>

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

#define GET_PATTERN 0x06

static permutation *f = NULL;
static pad *p = NULL;

static int spongeprg_f(permutation *p __attribute__((unused)))
{
	assert_false(1);

	return -1;
}

static int spongeprg_xor(permutation *p, const size_t start_bit_idx,
		const unsigned char *input, const size_t input_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(input);
	check_expected(input_bit_len);

	return mock_type(int);
}

static int spongeprg_get(permutation *p, const size_t start_bit_idx,
		unsigned char *output, const size_t output_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(output);
	check_expected(output_bit_len);

	memset(output, GET_PATTERN, (output_bit_len + 7) / 8);

	return mock_type(int);
}

static int spongeprg_pf(pad *p, permutation *f, const size_t remaining_bits)
{
	check_expected(p);
	check_expected(f);
	check_expected(remaining_bits);

	return mock_type(int);
}

static void spongeprg_init_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->f = spongeprg_f;
	f->xor = spongeprg_xor;
	f->get = spongeprg_get;
	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->pf = spongeprg_pf;
	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
}

static void spongeprg_init_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
}

static void spongeprg_init_f_null(void **state __attribute__((unused)))
{
	assert_null(spongeprg_init(NULL, p, CREATE_RATE, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_p_null(void **state __attribute__((unused)))
{
	assert_null(spongeprg_init(f, NULL, CREATE_RATE, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_zero(void **state __attribute__((unused)))
{
	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongeprg_init(f, p, 0, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	assert_null(spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_bs_zero(void **state __attribute__((unused)))
{
	assert_null(spongeprg_init(f, p, CREATE_RATE, 0));
}

static void spongeprg_init_rate_zero_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(spongeprg_init(f, p, 0, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_gt_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH + 8;

	assert_null(spongeprg_init(f, p, CREATE_WIDTH + 8, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_eq_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH;

	assert_null(spongeprg_init(f, p, CREATE_WIDTH, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_ne_prate(void **state __attribute__((unused)))
{
	assert_null(spongeprg_init(f, p, CREATE_RATE + 8, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE + 1;

	assert_null(spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE;

	assert_null(spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE));
}

static void spongeprg_init_bs_gt_maxbs(void **state __attribute__((unused)))
{
	assert_null(spongeprg_init(f, p, CREATE_RATE,
				(CREATE_RATE - CREATE_MIN_RATE + 7) / 8));
}

static void spongeprg_init_rate_odd(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	spongeprg *w;

	size_t rate;
	for (rate = CREATE_RATE + 1; rate < CREATE_RATE + 8; rate++) {
		p->rate = rate;

		__activate_wrap_alloc = 1;

		w = spongeprg_init(f, p, rate, CREATE_BLOCK_SIZE);

		__activate_wrap_alloc = 0;

		assert_non_null(w);

		assert_true(w->f == f);
		assert_true(w->p == p);
		assert_true(w->rate == rate);
		assert_true(w->block_size == CREATE_BLOCK_SIZE);

		spongeprg_free(w);
	}
}

static void spongeprg_init_width_odd(void **state __attribute__((unused)))
{
	size_t width;
	for (width = CREATE_WIDTH + 1; width < CREATE_WIDTH + 7; width++) {
		f->width = width;
		assert_null(spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE));
	}
}

static void spongeprg_init_noalloc(void **state __attribute__((unused)))
{
	/* spongeprg_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	spongeprg *w = spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE);

	__activate_wrap_alloc = 0;

	assert_null(w);
}

static void spongeprg_init_alloc_limited(void **state __attribute__((unused)))
{
	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	spongeprg *w = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		w = spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE);
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

	spongeprg_free(w);
}

static void spongeprg_init_normal(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	spongeprg *w = spongeprg_init(f, p, CREATE_RATE, CREATE_BLOCK_SIZE);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongeprg_free(w);
}

static void spongeprg_init_rate_max(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH - 1;

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	spongeprg *w = spongeprg_init(f, p, CREATE_WIDTH - 1, CREATE_BLOCK_SIZE);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_WIDTH - 1);
	assert_true(w->block_size == CREATE_BLOCK_SIZE);

	spongeprg_free(w);
}

static void spongeprg_init_bs_max(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	spongeprg *w = spongeprg_init(f, p, CREATE_RATE,
			(CREATE_RATE - CREATE_MIN_RATE - 1) / 8);

	__activate_wrap_alloc = 0;

	assert_non_null(w);

	assert_true(w->f == f);
	assert_true(w->p == p);
	assert_true(w->rate == CREATE_RATE);
	assert_true(w->block_size == (CREATE_RATE - CREATE_MIN_RATE - 1) / 8);

	spongeprg_free(w);
}

static void spongeprg_feed_setup(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_teardown(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_g_null(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_in_null(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_ilen_zero(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_in_null_ilen_zero(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_xor_fail(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_pf_fail(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_get_fail(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_normal(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_ilen_lt_bs(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_ilen_eq_bs(void **state __attribute__((unused)))
{
}

static void spongeprg_feed_ilen_gt_bs(void **state __attribute__((unused)))
{
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest spongeprg_init_tests[] = {
		unit_test_setup_teardown(spongeprg_init_f_null, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_p_null, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_zero, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_width_zero,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_bs_zero, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_zero_width_zero,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_gt_width,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_eq_width,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_ne_prate,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_lt_minrate,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_eq_minrate,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_bs_gt_maxbs,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_odd, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_width_odd, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_noalloc, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_alloc_limited,
				spongeprg_init_setup, spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_normal, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_rate_max, spongeprg_init_setup,
				spongeprg_init_teardown),
		unit_test_setup_teardown(spongeprg_init_bs_max, spongeprg_init_setup,
				spongeprg_init_teardown)
	};

	fprintf(stderr, "spongeprg_init:\n");
	res |= run_tests(spongeprg_init_tests);
	fprintf(stderr, "\n");

	const UnitTest spongeprg_feed_tests[] = {
		unit_test_setup_teardown(spongeprg_feed_g_null,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_in_null,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_ilen_zero,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_in_null_ilen_zero,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_xor_fail,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_pf_fail,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_get_fail,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_normal,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_ilen_lt_bs,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_ilen_eq_bs,
				spongeprg_feed_setup, spongeprg_feed_teardown),
		unit_test_setup_teardown(spongeprg_feed_ilen_gt_bs,
				spongeprg_feed_setup, spongeprg_feed_teardown)
	};

	fprintf(stderr, "spongeprg_feed:\n");
	res |= run_tests(spongeprg_feed_tests);
	fprintf(stderr, "\n");

	return res;
}
