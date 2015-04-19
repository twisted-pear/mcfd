#include <stdlib.h>
#include <string.h>

#include <pad.h>
#include <permutation.h>
#include <duplex.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_WIDTH 1600
#define CREATE_RATE 1024
#define CREATE_MIN_RATE 2
#define CREATE_MAX_ALLOC_SIZE (CREATE_RATE * 2)
#define CREATE_MAX_ALLOCS 10

#define INBUF_PATTERN 0xAA
#define OUTBUF_PATTERN 0x55

static permutation *f = NULL;
static pad *p = NULL;

static void duplex_init_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
}

static void duplex_init_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
}

static void duplex_init_f_null(void **state __attribute__((unused)))
{
	assert_null(duplex_init(NULL, p, CREATE_RATE));
}

static void duplex_init_p_null(void **state __attribute__((unused)))
{
	assert_null(duplex_init(f, NULL, CREATE_RATE));
}

static void duplex_init_rate_zero(void **state __attribute__((unused)))
{
	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(duplex_init(f, p, 0));
}

static void duplex_init_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	assert_null(duplex_init(f, p, CREATE_RATE));
}

static void duplex_init_rate_zero_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(duplex_init(f, p, 0));
}

static void duplex_init_rate_gt_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH + 8;

	assert_null(duplex_init(f, p, CREATE_WIDTH + 8));
}

static void duplex_init_rate_eq_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH;

	assert_null(duplex_init(f, p, CREATE_WIDTH));
}

static void duplex_init_rate_ne_prate(void **state __attribute__((unused)))
{
	assert_null(duplex_init(f, p, CREATE_RATE + 8));
}

static void duplex_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE + 1;

	assert_null(duplex_init(f, p, CREATE_RATE));
}

static void duplex_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE;

	assert_null(duplex_init(f, p, CREATE_RATE));
}

static void duplex_init_rate_odd(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	size_t rate;
	for (rate = CREATE_RATE + 1; rate < CREATE_RATE + 8; rate++) {
		p->rate = rate;

		__activate_wrap_alloc = 1;

		duplex *dp = duplex_init(f, p, rate);

		__activate_wrap_alloc = 0;

		assert_non_null(dp);

		assert_true(dp->f == f);
		assert_true(dp->p == p);
		assert_true(dp->rate == rate);
		assert_true(dp->max_duplex_rate <= (rate) - CREATE_MIN_RATE);

		duplex_free(dp);
	}
}

static void duplex_init_width_odd(void **state __attribute__((unused)))
{
	f->width = CREATE_WIDTH + 1;

	assert_null(duplex_init(f, p, CREATE_RATE));
}

static void duplex_init_noalloc(void **state __attribute__((unused)))
{
	/* duplex_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	duplex *dp = duplex_init(f, p, CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_null(dp);
}

static void duplex_init_alloc_limited(void **state __attribute__((unused)))
{
	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	duplex *dp = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		dp = duplex_init(f, p, CREATE_RATE);
		if (dp != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(dp);

	assert_true(dp->f == f);
	assert_true(dp->p == p);
	assert_true(dp->rate == CREATE_RATE);
	assert_true(dp->max_duplex_rate <= CREATE_RATE - CREATE_MIN_RATE);

	duplex_free(dp);
}

static void duplex_init_normal(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	duplex *dp = duplex_init(f, p, CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_non_null(dp);

	assert_true(dp->f == f);
	assert_true(dp->p == p);
	assert_true(dp->rate == CREATE_RATE);
	assert_true(dp->max_duplex_rate <= CREATE_RATE - CREATE_MIN_RATE);

	duplex_free(dp);
}

static void duplex_init_rate_max(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH - 1;

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	duplex *dp = duplex_init(f, p, CREATE_WIDTH - 1);

	__activate_wrap_alloc = 0;

	assert_non_null(dp);

	assert_true(dp->f == f);
	assert_true(dp->p == p);
	assert_true(dp->rate == CREATE_WIDTH - 1);
	assert_true(dp->max_duplex_rate <= (CREATE_WIDTH - 1) - CREATE_MIN_RATE);

	duplex_free(dp);
}

static int duplex_duplexing_order = 0;
static unsigned char *inbuf = NULL;
static unsigned char *outbuf = NULL;
static duplex *dp = NULL;

static int duplex_duplexing_f(permutation *p __attribute__((unused)))
{
	assert_false(1);

	return -1;
}

static int duplex_duplexing_xor(permutation *p, const size_t start_bit_idx,
		const unsigned char *input, const size_t input_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(input);
	check_expected(input_bit_len);

	assert_in_range(start_bit_idx, 0,
			(dp->rate % 8 == 0 ? dp->rate - 8 : (dp->rate / 8) * 8) + 1);
	if (input_bit_len != 0) {
		assert_in_range(input, inbuf, inbuf + ((dp->max_duplex_rate + 7) / 8));
	}
	assert_in_range(input_bit_len, 0, dp->max_duplex_rate - ((inbuf - input) * 8));
	assert_in_range(input_bit_len, 0, dp->rate - start_bit_idx);

	assert_int_equal(duplex_duplexing_order, 0);
	duplex_duplexing_order++;

	return mock_type(int);
}

static int duplex_duplexing_get(permutation *p, const size_t start_bit_idx,
		unsigned char *output, const size_t output_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(output);
	check_expected(output_bit_len);

	assert_in_range(start_bit_idx, 0,
			(dp->rate % 8 == 0 ? dp->rate - 8 : (dp->rate / 8) * 8) + 1);
	if (output_bit_len != 0) {
		assert_in_range(output, outbuf, outbuf + ((dp->rate + 7) / 8));
	}
	assert_in_range(output_bit_len, 0, dp->rate - ((outbuf - output) * 8));
	assert_in_range(output_bit_len, 0, dp->rate - start_bit_idx);

	assert_int_equal(duplex_duplexing_order, 2);
	duplex_duplexing_order++;

	return mock_type(int);
}

static int duplex_duplexing_pf(pad *p, permutation *f, const size_t remaining_bits)
{
	check_expected(p);
	check_expected(f);
	check_expected(remaining_bits);

	assert_in_range(remaining_bits, 0, dp->rate);

	assert_int_equal(duplex_duplexing_order, 1);
	duplex_duplexing_order++;

	return mock_type(int);
}

static void duplex_duplexing_setup(void **state __attribute__((unused)))
{
	duplex_duplexing_order = 0;

	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;
	f->f = duplex_duplexing_f;
	f->xor = duplex_duplexing_xor;
	f->get = duplex_duplexing_get;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
	p->pf = duplex_duplexing_pf;

	dp = duplex_init(f, p, CREATE_RATE);
	assert_non_null(dp);
	assert_true(dp->f == f);
	assert_true(dp->p == p);
	assert_true(dp->rate == CREATE_RATE);
	assert_true(dp->max_duplex_rate <= CREATE_RATE - CREATE_MIN_RATE);

	inbuf = calloc(1, CREATE_RATE / 8);
	assert_non_null(inbuf);

	memset(inbuf, INBUF_PATTERN, CREATE_RATE / 8);

	outbuf = calloc(1, CREATE_RATE / 8);
	assert_non_null(outbuf);

	memset(outbuf, OUTBUF_PATTERN, CREATE_RATE / 8);
}

static void duplex_duplexing_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
	duplex_free(dp);
	free(inbuf);
	free(outbuf);
}

static void duplex_duplexing_success(void)
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 0);

	duplex_duplexing_order = 0;

	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, CREATE_RATE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}
}

static void duplex_duplexing_dp_null(void **state __attribute__((unused)))
{
	assert_int_equal(duplex_duplexing(NULL, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, CREATE_RATE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_in_null_ilen_nonzero(void **state __attribute__((unused)))
{
	assert_int_equal(duplex_duplexing(dp, NULL, CREATE_RATE - CREATE_MIN_RATE, outbuf,
				CREATE_RATE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_in_null_ilen_zero(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, NULL);
	expect_value(duplex_duplexing_xor, input_bit_len, 0);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, 0);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, NULL, 0, outbuf, CREATE_RATE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_in_nonnull_ilen_zero(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, 0);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, 0);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, 0, outbuf, CREATE_RATE),
			CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_out_null_olen_nonzero(void **state __attribute__((unused)))
{
	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE, NULL,
				CREATE_RATE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_out_null_olen_zero(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, NULL);
	expect_value(duplex_duplexing_get, output_bit_len, 0);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE, NULL,
				0), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_out_nonnull_olen_zero(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, 0);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, 0), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_ilen_gt_drate(void **state __attribute__((unused)))
{
	assert_int_equal(duplex_duplexing(dp, inbuf, dp->max_duplex_rate + 1, outbuf,
				CREATE_RATE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_ilen_1_left(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, dp->max_duplex_rate - 1);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, dp->max_duplex_rate - 1);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, dp->max_duplex_rate - 1, outbuf,
				CREATE_RATE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_ilen_max(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, dp->max_duplex_rate);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, dp->max_duplex_rate);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, dp->max_duplex_rate, outbuf,
				CREATE_RATE), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_olen_gt_rate(void **state __attribute__((unused)))
{
	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, dp->rate + 1), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_olen_1_left(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, dp->rate - 1);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, dp->rate - 1), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_olen_max(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, dp->rate);
	will_return(duplex_duplexing_get, 0);

	assert_int_equal(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, dp->rate), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}

	duplex_duplexing_success();
}

static void duplex_duplexing_xor_fail(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 1);

	expect_assert_failure(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, CREATE_RATE));

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}
}

static void duplex_duplexing_pf_fail(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 1);

	expect_assert_failure(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, CREATE_RATE));

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}
}

static void duplex_duplexing_get_fail(void **state __attribute__((unused)))
{
	expect_value(duplex_duplexing_xor, p, f);
	expect_value(duplex_duplexing_xor, start_bit_idx, 0);
	expect_value(duplex_duplexing_xor, input, inbuf);
	expect_value(duplex_duplexing_xor, input_bit_len, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_xor, 0);

	expect_value(duplex_duplexing_pf, p, p);
	expect_value(duplex_duplexing_pf, f, f);
	expect_value(duplex_duplexing_pf, remaining_bits, CREATE_RATE - CREATE_MIN_RATE);
	will_return(duplex_duplexing_pf, 0);

	expect_value(duplex_duplexing_get, p, f);
	expect_value(duplex_duplexing_get, start_bit_idx, 0);
	expect_value(duplex_duplexing_get, output, outbuf);
	expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);
	will_return(duplex_duplexing_get, 1);

	expect_assert_failure(duplex_duplexing(dp, inbuf, CREATE_RATE - CREATE_MIN_RATE,
				outbuf, CREATE_RATE));

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(inbuf[i], INBUF_PATTERN);
		assert_int_equal(outbuf[i], OUTBUF_PATTERN);
	}
}

static void duplex_duplexing_diff_ilens(void **state __attribute__((unused)))
{
	expect_value_count(duplex_duplexing_xor, input, inbuf, -1);
	expect_value_count(duplex_duplexing_xor, p, f, -1);
	expect_value_count(duplex_duplexing_xor, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_xor, 0, -1);

	expect_value_count(duplex_duplexing_pf, p, p, -1);
	expect_value_count(duplex_duplexing_pf, f, f, -1);
	will_return_count(duplex_duplexing_pf, 0, -1);

	expect_value_count(duplex_duplexing_get, output, outbuf, -1);
	expect_value_count(duplex_duplexing_get, p, f, -1);
	expect_value_count(duplex_duplexing_get, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_get, 0, -1);

	size_t ilen;
	for (ilen = 0; ilen <= CREATE_RATE - CREATE_MIN_RATE; ilen++) {
		expect_value(duplex_duplexing_xor, input_bit_len, ilen);
		expect_value(duplex_duplexing_pf, remaining_bits, ilen);

		expect_value(duplex_duplexing_get, output_bit_len, CREATE_RATE);

		duplex_duplexing_order = 0;

		assert_int_equal(duplex_duplexing(dp, inbuf, ilen, outbuf, CREATE_RATE),
				CONSTR_SUCCESS);

		size_t i;
		for (i = 0; i < CREATE_RATE / 8; i++) {
			assert_int_equal(inbuf[i], INBUF_PATTERN);
			assert_int_equal(outbuf[i], OUTBUF_PATTERN);
		}
	}
}

static void duplex_duplexing_diff_olens(void **state __attribute__((unused)))
{
	expect_value_count(duplex_duplexing_xor, input, inbuf, -1);
	expect_value_count(duplex_duplexing_xor, p, f, -1);
	expect_value_count(duplex_duplexing_xor, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_xor, 0, -1);

	expect_value_count(duplex_duplexing_pf, p, p, -1);
	expect_value_count(duplex_duplexing_pf, f, f, -1);
	will_return_count(duplex_duplexing_pf, 0, -1);

	expect_value_count(duplex_duplexing_get, output, outbuf, -1);
	expect_value_count(duplex_duplexing_get, p, f, -1);
	expect_value_count(duplex_duplexing_get, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_get, 0, -1);

	size_t olen;
	for (olen = 0; olen <= CREATE_RATE; olen++) {
		expect_value(duplex_duplexing_xor, input_bit_len,
				CREATE_RATE - CREATE_MIN_RATE);
		expect_value(duplex_duplexing_pf, remaining_bits,
				CREATE_RATE - CREATE_MIN_RATE);

		expect_value(duplex_duplexing_get, output_bit_len, olen);

		duplex_duplexing_order = 0;

		assert_int_equal(duplex_duplexing(dp, inbuf,
					CREATE_RATE - CREATE_MIN_RATE, outbuf, olen),
				CONSTR_SUCCESS);

		size_t i;
		for (i = 0; i < CREATE_RATE / 8; i++) {
			assert_int_equal(inbuf[i], INBUF_PATTERN);
			assert_int_equal(outbuf[i], OUTBUF_PATTERN);
		}
	}
}

static void duplex_duplexing_diff_rates(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);
	f->width = CREATE_WIDTH;
	f->f = duplex_duplexing_f;
	f->xor = duplex_duplexing_xor;
	f->get = duplex_duplexing_get;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);
	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
	p->pf = duplex_duplexing_pf;

	inbuf = calloc(1, CREATE_RATE / 8);
	assert_non_null(inbuf);
	memset(inbuf, INBUF_PATTERN, CREATE_RATE / 8);

	outbuf = calloc(1, CREATE_RATE / 8);
	assert_non_null(outbuf);
	memset(outbuf, OUTBUF_PATTERN, CREATE_RATE / 8);

	expect_value_count(duplex_duplexing_xor, input, inbuf, -1);
	expect_value_count(duplex_duplexing_xor, p, f, -1);
	expect_value_count(duplex_duplexing_xor, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_xor, 0, -1);

	expect_value_count(duplex_duplexing_pf, p, p, -1);
	expect_value_count(duplex_duplexing_pf, f, f, -1);
	will_return_count(duplex_duplexing_pf, 0, -1);

	expect_value_count(duplex_duplexing_get, output, outbuf, -1);
	expect_value_count(duplex_duplexing_get, p, f, -1);
	expect_value_count(duplex_duplexing_get, start_bit_idx, 0, -1);
	will_return_count(duplex_duplexing_get, 0, -1);

	size_t rate;
	for (rate = CREATE_MIN_RATE + 1; rate < CREATE_WIDTH; rate++) {
		p->rate = rate;

		dp = duplex_init(f, p, rate);
		assert_non_null(dp);
		assert_true(dp->f == f);
		assert_true(dp->p == p);
		assert_true(dp->rate == rate);
		assert_true(dp->max_duplex_rate <= rate - CREATE_MIN_RATE);

		expect_value(duplex_duplexing_xor, input_bit_len, rate - CREATE_MIN_RATE);
		expect_value(duplex_duplexing_pf, remaining_bits, rate - CREATE_MIN_RATE);

		expect_value(duplex_duplexing_get, output_bit_len, rate);

		duplex_duplexing_order = 0;

		assert_int_equal(duplex_duplexing(dp, inbuf, rate - CREATE_MIN_RATE,
					outbuf, rate), CONSTR_SUCCESS);

		duplex_free(dp);

		size_t i;
		for (i = 0; i < CREATE_RATE / 8; i++) {
			assert_int_equal(inbuf[i], INBUF_PATTERN);
			assert_int_equal(outbuf[i], OUTBUF_PATTERN);
		}
	}

	free(f);
	free(p);
	free(inbuf);
	free(outbuf);
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest duplex_init_tests[] = {
		unit_test_setup_teardown(duplex_init_f_null, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_p_null, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_zero, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_width_zero, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_zero_width_zero,
				duplex_init_setup, duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_gt_width, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_eq_width, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_ne_prate, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_lt_minrate, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_eq_minrate, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_odd, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_width_odd, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_noalloc, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_alloc_limited, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_normal, duplex_init_setup,
				duplex_init_teardown),
		unit_test_setup_teardown(duplex_init_rate_max, duplex_init_setup,
				duplex_init_teardown)
	};

	fprintf(stderr, "duplex_init:\n");
	res |= run_tests(duplex_init_tests);
	fprintf(stderr, "\n");

	const UnitTest duplex_duplexing_tests[] = {
		unit_test_setup_teardown(duplex_duplexing_dp_null,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_in_null_ilen_nonzero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_in_null_ilen_zero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_in_nonnull_ilen_zero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_out_null_olen_nonzero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_out_null_olen_zero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_out_nonnull_olen_zero,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_ilen_gt_drate,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_ilen_1_left,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_ilen_max,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_olen_gt_rate,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_olen_1_left,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_olen_max,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_xor_fail,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_pf_fail,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_get_fail,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_diff_ilens,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test_setup_teardown(duplex_duplexing_diff_olens,
				duplex_duplexing_setup, duplex_duplexing_teardown),
		unit_test(duplex_duplexing_diff_rates)
	};

	fprintf(stderr, "duplex_duplexing:\n");
	res |= run_tests(duplex_duplexing_tests);
	fprintf(stderr, "\n");

	return res;
}
