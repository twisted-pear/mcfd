#include <stdlib.h>
#include <string.h>

#include <pad.h>
#include <permutation.h>
#include <sponge.h>

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

#define TESTBUF_PATTERN 0xAA
#define TESTBUF_SIZE ((CREATE_WIDTH / 8) * 4)

static permutation *f = NULL;
static pad *p = NULL;

static void sponge_init_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
}

static void sponge_init_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
}

static void sponge_init_f_null(void **state __attribute__((unused)))
{
	assert_null(sponge_init(NULL, p, CREATE_RATE));
}

static void sponge_init_p_null(void **state __attribute__((unused)))
{
	assert_null(sponge_init(f, NULL, CREATE_RATE));
}

static void sponge_init_rate_zero(void **state __attribute__((unused)))
{
	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(sponge_init(f, p, 0));
}

static void sponge_init_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	assert_null(sponge_init(f, p, CREATE_RATE));
}

static void sponge_init_rate_zero_width_zero(void **state __attribute__((unused)))
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	assert_null(sponge_init(f, p, 0));
}

static void sponge_init_rate_gt_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH + 8;

	assert_null(sponge_init(f, p, CREATE_WIDTH + 8));
}

static void sponge_init_rate_eq_width(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH;

	assert_null(sponge_init(f, p, CREATE_WIDTH));
}

static void sponge_init_rate_ne_prate(void **state __attribute__((unused)))
{
	assert_null(sponge_init(f, p, CREATE_RATE + 8));
}

static void sponge_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE + 1;

	assert_null(sponge_init(f, p, CREATE_RATE));
}

static void sponge_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	p->min_bit_len = CREATE_RATE;

	assert_null(sponge_init(f, p, CREATE_RATE));
}

static void sponge_init_rate_odd(void **state __attribute__((unused)))
{
	p->rate = CREATE_RATE + 1;

	assert_null(sponge_init(f, p, CREATE_RATE + 1));
}

static void sponge_init_width_odd(void **state __attribute__((unused)))
{
	f->width = CREATE_WIDTH + 1;

	assert_null(sponge_init(f, p, CREATE_RATE));
}

static void sponge_init_noalloc(void **state __attribute__((unused)))
{
	/* sponge_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	sponge *sp = sponge_init(f, p, CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_null(sp);
}

static void sponge_init_alloc_limited(void **state __attribute__((unused)))
{
	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	sponge *sp = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		sp = sponge_init(f, p, CREATE_RATE);
		if (sp != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(sp);

	assert_true(sp->f == f);
	assert_true(sp->p == p);
	assert_true(sp->rate == CREATE_RATE);

	sponge_free(sp);
}

static void sponge_init_normal(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	sponge *sp = sponge_init(f, p, CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_non_null(sp);

	assert_true(sp->f == f);
	assert_true(sp->p == p);
	assert_true(sp->rate == CREATE_RATE);

	sponge_free(sp);
}

static void sponge_init_rate_max(void **state __attribute__((unused)))
{
	p->rate = CREATE_WIDTH - 8;

	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	sponge *sp = sponge_init(f, p, CREATE_WIDTH - 8);

	__activate_wrap_alloc = 0;

	assert_non_null(sp);

	assert_true(sp->f == f);
	assert_true(sp->p == p);
	assert_true(sp->rate == CREATE_WIDTH - 8);

	sponge_free(sp);
}

static int sponge_order = 0;
static unsigned char *testbuf = NULL;
static sponge *sp = NULL;

static int sponge_f(permutation *p __attribute__((unused)))
{
	check_expected(p);

	assert_int_equal(sponge_order, 1);
	sponge_order--;

	return mock_type(int);
}

static int sponge_xor(permutation *p, const size_t start_bit_idx,
		const unsigned char *input, const size_t input_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(input);
	check_expected(input_bit_len);

	assert_in_range(start_bit_idx, 0, sp->rate + 1);
	assert_in_range(input, testbuf, testbuf + TESTBUF_SIZE);
	assert_in_range(input_bit_len, 0, (TESTBUF_SIZE * 8) - ((testbuf - input) * 8));
	assert_in_range(input_bit_len, 0, sp->rate - start_bit_idx);

	assert_int_equal(sponge_order, 0);
	sponge_order++;

	return mock_type(int);
}

static int sponge_get(permutation *p, const size_t start_bit_idx,
		unsigned char *output, const size_t output_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(output);
	check_expected(output_bit_len);

	assert_in_range(start_bit_idx, 0, sp->rate + 1);
	assert_in_range(output, testbuf, testbuf + TESTBUF_SIZE);
	assert_in_range(output_bit_len, 0, (TESTBUF_SIZE * 8) - ((testbuf - output) * 8));
	assert_in_range(output_bit_len, 0, sp->rate - start_bit_idx);

	assert_int_equal(sponge_order, 0);
	sponge_order++;

	return mock_type(int);
}

static int sponge_pf(pad *p, permutation *f, const size_t remaining_bits)
{
	check_expected(p);
	check_expected(f);
	check_expected(remaining_bits);

	assert_in_range(remaining_bits, 0, sp->rate);

	assert_int_equal(sponge_order, 1);
	sponge_order--;

	return mock_type(int);
}

static void sponge_squeeze_success(const size_t expected_remaining)
{
	sponge_order = 0;

	assert_int_equal(sponge_absorb(sp, testbuf, TESTBUF_SIZE * 8), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	assert_int_equal(sponge_absorb_final(sp), CONSTR_FAILURE);

	for (i = 0; i < TESTBUF_SIZE / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	assert_true(expected_remaining % 8 == 0);

	size_t remaining_bits = expected_remaining;
	size_t out_bits = TESTBUF_SIZE * 8;
	unsigned char *out_buf = testbuf;

	do {
		size_t bits_taken = remaining_bits > out_bits ? out_bits : remaining_bits;

		expect_value(sponge_get, p, f);
		expect_value(sponge_get, start_bit_idx, sp->rate - remaining_bits);
		expect_value(sponge_get, output, out_buf);
		expect_value(sponge_get, output_bit_len, bits_taken);
		will_return(sponge_get, 0);

		remaining_bits -= bits_taken;
		out_bits -= bits_taken;
		out_buf += bits_taken / 8;

		if (remaining_bits == 0) {
			expect_value(sponge_f, p, f);
			will_return(sponge_f, 0);

			remaining_bits = sp->rate;
		}
	} while (out_bits != 0);

	assert_int_equal(sponge_squeeze(sp, testbuf, TESTBUF_SIZE * 8), CONSTR_SUCCESS);

	for (i = 0; i < TESTBUF_SIZE / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}
}

static void sponge_absorb_success(const size_t expected_remaining, const int final_only)
{
	sponge_order = 0;

	assert_int_equal(sponge_squeeze(sp, testbuf, TESTBUF_SIZE * 8), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	if (final_only == 0) {
		assert_true(expected_remaining % 8 == 0);

		size_t remaining_bits = expected_remaining;
		size_t in_bits = TESTBUF_SIZE * 8;
		unsigned char *in_buf = testbuf;

		do {
			size_t bits_to_full = sp->rate - remaining_bits;
			size_t bits_taken = bits_to_full > in_bits ? in_bits
				: bits_to_full;

			expect_value(sponge_xor, p, f);
			expect_value(sponge_xor, start_bit_idx, remaining_bits);
			expect_value(sponge_xor, input, in_buf);
			expect_value(sponge_xor, input_bit_len, bits_taken);
			will_return(sponge_xor, 0);

			remaining_bits += bits_taken;
			in_bits -= bits_taken;
			in_buf += bits_taken / 8;

			if (remaining_bits == sp->rate) {
				expect_value(sponge_f, p, f);
				will_return(sponge_f, 0);

				remaining_bits = 0;
			}
		} while (in_bits != 0);

		assert_int_equal(sponge_absorb(sp, testbuf, TESTBUF_SIZE * 8),
				CONSTR_SUCCESS);

		for (i = 0; i < TESTBUF_SIZE / 8; i++) {
			assert_int_equal(testbuf[i], TESTBUF_PATTERN);
		}
	}

	expect_value(sponge_pf, p, p);
	expect_value(sponge_pf, f, f);
	expect_in_range(sponge_pf, remaining_bits, 0, sp->rate - 1);
	will_return(sponge_pf, 0);

	assert_int_equal(sponge_absorb_final(sp), CONSTR_SUCCESS);

	for (i = 0; i < TESTBUF_SIZE / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}
}

static void sponge_absorb_setup(void **state __attribute__((unused)))
{
	sponge_order = 0;

	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;
	f->f = sponge_f;
	f->xor = sponge_xor;
	f->get = sponge_get;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);

	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
	p->pf = sponge_pf;

	sp = sponge_init(f, p, CREATE_RATE);
	assert_non_null(sp);

	assert_true(sp->f == f);
	assert_true(sp->p == p);
	assert_true(sp->rate == CREATE_RATE);

	testbuf = calloc(1, TESTBUF_SIZE);
	assert_non_null(testbuf);

	memset(testbuf, TESTBUF_PATTERN, TESTBUF_SIZE);
}

static void sponge_absorb_teardown(void **state __attribute__((unused)))
{
	free(f);
	free(p);
	sponge_free(sp);
	free(testbuf);
}

static void sponge_absorb_sp_null(void **state __attribute__((unused)))
{
	assert_int_equal(sponge_absorb(NULL, testbuf, TESTBUF_SIZE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	sponge_absorb_success(0, 0);
	sponge_squeeze_success(sp->rate);
}

static void sponge_absorb_in_null(void **state __attribute__((unused)))
{
	assert_int_equal(sponge_absorb(sp, NULL, 0), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	sponge_absorb_success(0, 0);
	sponge_squeeze_success(sp->rate);
}

static void sponge_absorb_wrong_phase(void **state __attribute__((unused)))
{
	sponge_absorb_success(0, 0);

	assert_int_equal(sponge_absorb(sp, testbuf, TESTBUF_SIZE), CONSTR_FAILURE);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	assert_int_equal(sponge_absorb_final(sp), CONSTR_FAILURE);

	for (i = 0; i < TESTBUF_SIZE; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	sponge_squeeze_success(sp->rate);
}

static void sponge_absorb_len_zero(void **state __attribute__((unused)))
{
	expect_value(sponge_xor, p, f);
	expect_value(sponge_xor, start_bit_idx, 0);
	expect_value(sponge_xor, input, testbuf);
	expect_value(sponge_xor, input_bit_len, 0);
	will_return(sponge_xor, 0);

	assert_int_equal(sponge_absorb(sp, testbuf, 0), CONSTR_SUCCESS);

	size_t i;
	for (i = 0; i < TESTBUF_SIZE; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}

	sponge_absorb_success(0, 0);
	sponge_squeeze_success(sp->rate);
}

static void sponge_absorb_len_gt_rate(void **state __attribute__((unused)))
{
}

static void sponge_absorb_len_eq_rate(void **state __attribute__((unused)))
{
}

static void sponge_absorb_len_1_left(void **state __attribute__((unused)))
{
}

static void sponge_absorb_len_odd(void **state __attribute__((unused)))
{
}

static void sponge_absorb_xor_fail(void **state __attribute__((unused)))
{
}

static void sponge_absorb_f_fail(void **state __attribute__((unused)))
{
}

static void sponge_absorb_pf_fail(void **state __attribute__((unused)))
{
}

static void sponge_absorb_multiple_diff_splits(void **state __attribute__((unused)))
{
}

static void sponge_absorb_diff_lens(void **state __attribute__((unused)))
{
}

static void sponge_absorb_diff_rates(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_setup(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_teardown(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_sp_null(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_out_null(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_wrong_phase(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_len_zero(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_len_gt_rate(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_len_eq_rate(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_len_1_left(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_len_odd(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_get_fail(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_f_fail(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_multiple_diff_splits(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_diff_lens(void **state __attribute__((unused)))
{
}

static void sponge_squeeze_diff_rates(void **state __attribute__((unused)))
{
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest sponge_init_tests[] = {
		unit_test_setup_teardown(sponge_init_f_null, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_p_null, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_zero, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_width_zero, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_zero_width_zero,
				sponge_init_setup, sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_gt_width, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_eq_width, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_ne_prate, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_lt_minrate, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_eq_minrate, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_odd, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_width_odd, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_noalloc, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_alloc_limited, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_normal, sponge_init_setup,
				sponge_init_teardown),
		unit_test_setup_teardown(sponge_init_rate_max, sponge_init_setup,
				sponge_init_teardown)
	};

	fprintf(stderr, "sponge_init:\n");
	res |= run_tests(sponge_init_tests);
	fprintf(stderr, "\n");

	const UnitTest sponge_absorb_tests[] = {
		unit_test_setup_teardown(sponge_absorb_sp_null,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_in_null,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_wrong_phase,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_len_zero,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_len_gt_rate,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_len_eq_rate,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_len_1_left,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_len_odd,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_xor_fail,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_f_fail,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_pf_fail,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_multiple_diff_splits,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test_setup_teardown(sponge_absorb_diff_lens,
				sponge_absorb_setup, sponge_absorb_teardown),
		unit_test(sponge_absorb_diff_rates)
	};

	fprintf(stderr, "sponge_absorb:\n");
	res |= run_tests(sponge_absorb_tests);
	fprintf(stderr, "\n");

	const UnitTest sponge_squeeze_tests[] = {
		unit_test_setup_teardown(sponge_squeeze_sp_null,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_out_null,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_wrong_phase,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_len_zero,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_len_gt_rate,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_len_eq_rate,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_len_1_left,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_len_odd,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_get_fail,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_f_fail,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_multiple_diff_splits,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test_setup_teardown(sponge_squeeze_diff_lens,
				sponge_squeeze_setup, sponge_squeeze_teardown),
		unit_test(sponge_squeeze_diff_rates)
	};

	fprintf(stderr, "sponge_sqeeze:\n");
	res |= run_tests(sponge_squeeze_tests);
	fprintf(stderr, "\n");

	return res;
}
