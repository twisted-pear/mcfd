#include <stdlib.h>
#include <string.h>

#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>
#include <pad.h>
#include <permutation.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_WIDTH 1600
#define CREATE_RATE 1024
#define CREATE_MAX_ALLOC_SIZE ((EXPECTED_WIDTH / 8) * 2)
#define CREATE_MAX_ALLOCS 10

#define EXPECTED_WIDTH 1600
#define EXPECTED_MIN_PAD_SIZE 2

#define TESTBUF_PATTERN 0xAA
#define GET_TEST_PATTERN 0x55

static void keccakF_1600_init_noalloc(void **state __attribute__((unused)))
{
	/* keccakF_1600_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	permutation *f = keccakF_1600_init();

	__activate_wrap_alloc = 0;

	assert_null(f);
}

static void keccakF_1600_init_alloc_limited(void **state __attribute__((unused)))
{
	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	permutation *f = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		f = keccakF_1600_init();
		if (f != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(f);

	assert_true(f->width == EXPECTED_WIDTH);
	assert_non_null(f->f);
	assert_non_null(f->xor);
	assert_non_null(f->get);

	keccakF_1600_free(f);
}

static void keccakF_1600_init_normal(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	permutation *f = keccakF_1600_init();

	__activate_wrap_alloc = 0;

	assert_non_null(f);

	assert_true(f->width == EXPECTED_WIDTH);
	assert_non_null(f->f);
	assert_non_null(f->xor);
	assert_non_null(f->get);

	keccakF_1600_free(f);
}

static permutation *f = NULL;
static unsigned char *testbuf = NULL;

static void keccakF_1600_xor_setup(void **state __attribute__((unused)))
{
	f = keccakF_1600_init();
	assert_non_null(f);

	assert_true(f->width == EXPECTED_WIDTH);
	assert_non_null(f->f);
	assert_non_null(f->xor);
	assert_non_null(f->get);

	testbuf = calloc(EXPECTED_WIDTH / 8, 1);
	assert_non_null(testbuf);

	memset(testbuf, TESTBUF_PATTERN, EXPECTED_WIDTH / 8);

	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}
}

static void keccakF_1600_xor_teardown(void **state __attribute__((unused)))
{
	keccakF_1600_free(f);
	free(testbuf);
}

static void keccakF_1600_xor_f_null(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(NULL, 0, testbuf, EXPECTED_WIDTH), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_start_odd(void **state __attribute__((unused)))
{
	size_t start_idx;
	for (start_idx = 1; start_idx < 8; start_idx++) {
		assert_int_equal(f->xor(f, start_idx, testbuf,
					EXPECTED_WIDTH - start_idx), 1);

		assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
		size_t i;
		for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], 0);
		}

		memset(testbuf, TESTBUF_PATTERN, EXPECTED_WIDTH / 8);
	}
}

static void keccakF_1600_xor_start_gt_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, EXPECTED_WIDTH + 8, NULL, 0), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_start_eq_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, EXPECTED_WIDTH, NULL, 0), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_in_null_len_nonzero(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, 0, NULL, CREATE_RATE), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_in_null_len_zero(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, 0, NULL, 0), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_in_nonnull_len_zero(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, 0, testbuf, 0), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_start_len_gt_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, EXPECTED_WIDTH - CREATE_RATE + 8, testbuf,
				CREATE_RATE), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_xor_start_len_eq_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->xor(f, EXPECTED_WIDTH - CREATE_RATE, testbuf,
				CREATE_RATE), 0);

	memset(testbuf, 0, EXPECTED_WIDTH / 8);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < (EXPECTED_WIDTH - CREATE_RATE) / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
	for (i = (EXPECTED_WIDTH - CREATE_RATE) / 8; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], TESTBUF_PATTERN);
	}
}

static void keccakF_1600_xor_diff_lens(void **state __attribute__((unused)))
{
	size_t len;
	for (len = 0; len <= EXPECTED_WIDTH; len++) {
		permutation *f = keccakF_1600_init();
		assert_non_null(f);
		assert_true(f->width == EXPECTED_WIDTH);
		assert_non_null(f->f);
		assert_non_null(f->xor);
		assert_non_null(f->get);

		assert_int_equal(f->xor(f, 0, testbuf, len), 0);

		memset(testbuf, 0, EXPECTED_WIDTH / 8);

		assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
		size_t i;
		for (i = 0; i < len / 8; i++) {
			assert_int_equal(testbuf[i], TESTBUF_PATTERN);
		}
		if (len % 8 != 0) {
			assert_int_equal(testbuf[i], TESTBUF_PATTERN >> (8 - (len % 8)));
			i++;
		}
		for (; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], 0);
		}

		memset(testbuf, TESTBUF_PATTERN, EXPECTED_WIDTH / 8);
		keccakF_1600_free(f);
	}
}

static void keccakF_1600_get_setup(void **state __attribute__((unused)))
{
	f = keccakF_1600_init();
	assert_non_null(f);

	assert_true(f->width == EXPECTED_WIDTH);
	assert_non_null(f->f);
	assert_non_null(f->xor);
	assert_non_null(f->get);

	testbuf = calloc(EXPECTED_WIDTH / 8, 1);
	assert_non_null(testbuf);

	memset(testbuf, GET_TEST_PATTERN, EXPECTED_WIDTH / 8);

	assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);

	memset(testbuf, 0, EXPECTED_WIDTH / 8);
}

static void keccakF_1600_get_teardown(void **state __attribute__((unused)))
{
	keccakF_1600_free(f);
	free(testbuf);
}

static void keccakF_1600_get_f_null(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(NULL, 0, testbuf, EXPECTED_WIDTH), 1);

	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_start_odd(void **state __attribute__((unused)))
{
	size_t start_idx;
	for (start_idx = 1; start_idx < 8; start_idx++) {
		assert_int_equal(f->get(f, start_idx, testbuf,
					EXPECTED_WIDTH - start_idx), 1);

		size_t i;
		for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], 0);
		}

		assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
		for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], GET_TEST_PATTERN);
		}

		memset(testbuf, 0, EXPECTED_WIDTH / 8);
	}
}

static void keccakF_1600_get_start_gt_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, EXPECTED_WIDTH + 8, NULL, 0), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_start_eq_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, EXPECTED_WIDTH, NULL, 0), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_out_null_len_nonzero(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, 0, NULL, CREATE_RATE), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_out_null_len_zero(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, 0, NULL, 0), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_out_nonnull_len_zero(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, 0, testbuf, 0), 0);

	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_start_len_gt_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, EXPECTED_WIDTH - CREATE_RATE + 8, testbuf,
				CREATE_RATE), 1);

	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
}

static void keccakF_1600_get_start_len_eq_width(void **state __attribute__((unused)))
{
	assert_int_equal(f->get(f, EXPECTED_WIDTH - CREATE_RATE, testbuf,
				CREATE_RATE), 0);

	size_t i;
	for (i = 0; i < CREATE_RATE / 8; i++) {
		assert_int_equal(testbuf[i], GET_TEST_PATTERN);
	}
	for (; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], 0);
	}
}

static void keccakF_1600_get_diff_lens(void **state __attribute__((unused)))
{
	size_t len;
	for (len = 0; len <= EXPECTED_WIDTH; len++) {
		permutation *f = keccakF_1600_init();
		assert_non_null(f);
		assert_true(f->width == EXPECTED_WIDTH);
		assert_non_null(f->f);
		assert_non_null(f->xor);
		assert_non_null(f->get);
		memset(testbuf, GET_TEST_PATTERN, EXPECTED_WIDTH / 8);
		assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);
		memset(testbuf, 0, EXPECTED_WIDTH / 8);

		assert_int_equal(f->get(f, 0, testbuf, len), 0);

		size_t i;
		for (i = 0; i < len / 8; i++) {
			assert_int_equal(testbuf[i], GET_TEST_PATTERN);
		}
		if (len % 8 != 0) {
			assert_int_equal(testbuf[i],
					(GET_TEST_PATTERN << (8 - (len % 8))) & 0xFF);
			i++;
		}
		for (; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], 0);
		}

		assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
		for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], GET_TEST_PATTERN);
		}

		keccakF_1600_free(f);
	}
}

static void keccakF_1600_f_setup(void **state __attribute__((unused)))
{
}

static void keccakF_1600_f_teardown(void **state __attribute__((unused)))
{
}

static void keccakF_1600_f_f_null(void **state __attribute__((unused)))
{
}

static void keccakF_1600_f_all_zero(void **state __attribute__((unused)))
{
}

static void keccakF_1600_f_all_one(void **state __attribute__((unused)))
{
}

static void keccakF_1600_f_pattern(void **state __attribute__((unused)))
{
}

static void keccakPad_10_1_init_rate_zero(void **state __attribute__((unused)))
{
	assert_null(keccakPad_10_1_init(0));
}

static void keccakPad_10_1_init_rate_lt_minrate(void **state __attribute__((unused)))
{
	assert_null(keccakPad_10_1_init(EXPECTED_MIN_PAD_SIZE - 1));
}

static void keccakPad_10_1_init_rate_eq_minrate(void **state __attribute__((unused)))
{
	assert_null(keccakPad_10_1_init(EXPECTED_MIN_PAD_SIZE));
}

static void keccakPad_10_1_init_rate_odd(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	pad *p = keccakPad_10_1_init(CREATE_RATE + 1);

	__activate_wrap_alloc = 0;

	assert_non_null(p);

	assert_true(p->rate == CREATE_RATE + 1);
	assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
	assert_non_null(p->pf);

	keccakPad_10_1_free(p);
}

static void keccakPad_10_1_init_noalloc(void **state __attribute__((unused)))
{
	/* keccakPad_10_1_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	pad *p = keccakPad_10_1_init(CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_null(p);
}

static void keccakPad_10_1_init_alloc_limited(void **state __attribute__((unused)))
{
	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	pad *p = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		p = keccakPad_10_1_init(CREATE_RATE);
		if (p != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(p);

	assert_true(p->rate == CREATE_RATE);
	assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
	assert_non_null(p->pf);

	keccakPad_10_1_free(p);
}

static void keccakPad_10_1_init_normal(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	pad *p = keccakPad_10_1_init(CREATE_RATE);

	__activate_wrap_alloc = 0;

	assert_non_null(p);

	assert_true(p->rate == CREATE_RATE);
	assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
	assert_non_null(p->pf);

	keccakPad_10_1_free(p);
}

static void keccakPad_10_1_init_rate_1_left(void **state __attribute__((unused)))
{
	/* FIXME: implementations using calloc can cheat */
	expect_in_range_count(__wrap_alloc, nmemb, 1, CREATE_MAX_ALLOC_SIZE, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, -1);

	__activate_wrap_alloc = 1;

	pad *p = keccakPad_10_1_init(EXPECTED_MIN_PAD_SIZE + 1);

	__activate_wrap_alloc = 0;

	assert_non_null(p);

	assert_true(p->rate == EXPECTED_MIN_PAD_SIZE + 1);
	assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
	assert_non_null(p->pf);

	keccakPad_10_1_free(p);
}

static int keccakPad_10_1_pf_f(permutation *p)
{
	check_expected(p);

	return mock_type(int);
}

static int keccakPad_10_1_pf_xor(permutation *p, const size_t start_bit_idx,
		const unsigned char *input, const size_t input_bit_len)
{
	check_expected(p);
	check_expected(start_bit_idx);
	check_expected(input);
	check_expected(input_bit_len);

	return mock_type(int);
}

static int keccakPad_10_1_pf_get(permutation *p __attribute__((unused)),
		const size_t start_bit_idx __attribute__((unused)),
		unsigned char *output __attribute__((unused)),
		const size_t output_bit_len __attribute__((unused)))
{
	assert_false(1);

	return -1;
}

static pad *p = NULL;

static void keccakPad_10_1_pf_setup(void **state __attribute__((unused)))
{
	f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;
	f->f = keccakPad_10_1_pf_f;
	f->xor = keccakPad_10_1_pf_xor;
	f->get = keccakPad_10_1_pf_get;

	p = keccakPad_10_1_init(CREATE_RATE);

	assert_non_null(p);

	assert_true(p->rate == CREATE_RATE);
	assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
	assert_non_null(p->pf);
}

static void keccakPad_10_1_pf_teardown(void **state __attribute__((unused)))
{
	free(f);
	keccakPad_10_1_free(p);
}

static void keccakPad_10_1_pf_p_null(void **state __attribute__((unused)))
{
	assert_int_equal(p->pf(NULL, f, 0), 1);
}

static void keccakPad_10_1_pf_f_null(void **state __attribute__((unused)))
{
	assert_int_equal(p->pf(p, NULL, 0), 1);
}

static void keccakPad_10_1_pf_p_null_f_null(void **state __attribute__((unused)))
{
	assert_int_equal(p->pf(NULL, NULL, 0), 1);
}

static void keccakPad_10_1_pf_remaining_gt_rate(void **state __attribute__((unused)))
{
	assert_int_equal(p->pf(p, f, CREATE_RATE + 1), 1);
}

static void keccakPad_10_1_pf_remaining_eq_rate(void **state __attribute__((unused)))
{
	assert_int_equal(p->pf(p, f, CREATE_RATE), 1);
}

static void keccakPad_10_1_pf_width_lt_rate(void **state __attribute__((unused)))
{
	f->width = CREATE_RATE - 1;

	assert_int_equal(p->pf(p, f, 0), 1);
}

static void keccakPad_10_1_pf_width_eq_rate(void **state __attribute__((unused)))
{
	f->width = CREATE_RATE;

	assert_int_equal(p->pf(p, f, 0), 1);
}

static void keccakPad_10_1_pf_xor_fail(void **state __attribute__((unused)))
{
	/* first xor fails */

	expect_memory(keccakPad_10_1_pf_xor, p, f, sizeof(permutation));
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, 0);
	expect_any(keccakPad_10_1_pf_xor, input);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 1);
	will_return(keccakPad_10_1_pf_xor, 1);

	assert_int_equal(p->pf(p, f, 0), 1);

	/* second xor fails */

	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, 0);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 1);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 1);

	assert_int_equal(p->pf(p, f, 0), 1);
}

static void keccakPad_10_1_pf_f_fail(void **state __attribute__((unused)))
{
	/* first f fails */

	expect_memory(keccakPad_10_1_pf_xor, p, f, sizeof(permutation));
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any(keccakPad_10_1_pf_xor, input);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 1);

	assert_int_equal(p->pf(p, f, CREATE_RATE - 1), 1);

	/* second f fails */

	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, 0);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 1);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 1);

	assert_int_equal(p->pf(p, f, 0), 1);
}

static void keccakPad_10_1_pf_remaining_zero(void **state __attribute__((unused)))
{
	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, 0);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 1);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 0);

	assert_int_equal(p->pf(p, f, 0), 0);
}

static void keccakPad_10_1_pf_remaining_even(void **state __attribute__((unused)))
{
	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 1);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 0);

	assert_int_equal(p->pf(p, f, CREATE_RATE - 8), 0);
}

static void keccakPad_10_1_pf_remaining_odd(void **state __attribute__((unused)))
{
	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 5);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 0);

	assert_int_equal(p->pf(p, f, CREATE_RATE - 4), 0);
}

static void keccakPad_10_1_pf_remaining_2_left(void **state __attribute__((unused)))
{
	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 7);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
	will_return(keccakPad_10_1_pf_f, 0);

	assert_int_equal(p->pf(p, f, CREATE_RATE - 2), 0);
}

static void keccakPad_10_1_pf_remaining_1_left(void **state __attribute__((unused)))
{
	expect_memory_count(keccakPad_10_1_pf_xor, p, f, sizeof(permutation), 2);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_value(keccakPad_10_1_pf_xor, start_bit_idx, CREATE_RATE - 8);
	expect_any_count(keccakPad_10_1_pf_xor, input, 2);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	expect_value(keccakPad_10_1_pf_xor, input_bit_len, 8);
	will_return(keccakPad_10_1_pf_xor, 0);
	will_return(keccakPad_10_1_pf_xor, 0);

	expect_memory_count(keccakPad_10_1_pf_f, p, f, sizeof(permutation), 2);
	will_return_count(keccakPad_10_1_pf_f, 0, 2);

	assert_int_equal(p->pf(p, f, CREATE_RATE - 1), 0);
}

static void keccakPad_10_1_pf_diff_rates(void **state __attribute__((unused)))
{
	permutation *f = calloc(1, sizeof(permutation));
	assert_non_null(f);

	f->width = CREATE_WIDTH;
	f->f = keccakPad_10_1_pf_f;
	f->xor = keccakPad_10_1_pf_xor;
	f->get = keccakPad_10_1_pf_get;

	size_t rate;
	for (rate = CREATE_RATE; rate < CREATE_RATE + 8; rate++) {
		pad *p = keccakPad_10_1_init(rate);
		assert_non_null(p);
		assert_true(p->rate == rate);
		assert_true(p->min_bit_len == EXPECTED_MIN_PAD_SIZE);
		assert_non_null(p->pf);

		size_t remaining;
		for (remaining = 0; remaining < rate; remaining++) {
			size_t start_idx_fst = ((remaining) / 8) * 8;
			size_t bit_len_fst = remaining % 8 + 1;
			size_t start_idx_snd = (rate % 8 == 0) ? (((rate / 8) - 1) * 8)
				: ((rate / 8) * 8);
			size_t bit_len_snd = (rate % 8 == 0) ? 8 : (rate % 8);

			expect_memory_count(keccakPad_10_1_pf_xor, p, f,
					sizeof(permutation), 2);
			expect_value(keccakPad_10_1_pf_xor, start_bit_idx, start_idx_fst);
			expect_value(keccakPad_10_1_pf_xor, start_bit_idx, start_idx_snd);
			expect_any_count(keccakPad_10_1_pf_xor, input, 2);
			expect_value(keccakPad_10_1_pf_xor, input_bit_len, bit_len_fst);
			expect_value(keccakPad_10_1_pf_xor, input_bit_len, bit_len_snd);
			will_return(keccakPad_10_1_pf_xor, 0);
			will_return(keccakPad_10_1_pf_xor, 0);

			expect_memory(keccakPad_10_1_pf_f, p, f, sizeof(permutation));
			will_return(keccakPad_10_1_pf_f, 0);
			if (remaining == rate - 1) {
				expect_memory(keccakPad_10_1_pf_f, p, f,
						sizeof(permutation));
				will_return(keccakPad_10_1_pf_f, 0);
			}

			assert_int_equal(p->pf(p, f, remaining), 0);
		}

		keccakPad_10_1_free(p);
	}

	free(f);
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest keccakF_1600_init_tests[] = {
		unit_test(keccakF_1600_init_noalloc),
		unit_test(keccakF_1600_init_alloc_limited),
		unit_test(keccakF_1600_init_normal)
	};

	fprintf(stderr, "keccakF_1600_init:\n");
	res |= run_tests(keccakF_1600_init_tests);
	fprintf(stderr, "\n");

	const UnitTest keccakF_1600_xor_tests[] = {
		unit_test_setup_teardown(keccakF_1600_xor_f_null, keccakF_1600_xor_setup,
				keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_start_odd,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_start_gt_width,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_start_eq_width,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_in_null_len_nonzero,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_in_null_len_zero,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_in_nonnull_len_zero,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_start_len_gt_width,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_start_len_eq_width,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown),
		unit_test_setup_teardown(keccakF_1600_xor_diff_lens,
				keccakF_1600_xor_setup, keccakF_1600_xor_teardown)
	};

	fprintf(stderr, "keccakF_1600_xor:\n");
	res |= run_tests(keccakF_1600_xor_tests);
	fprintf(stderr, "\n");

	const UnitTest keccakF_1600_get_tests[] = {
		unit_test_setup_teardown(keccakF_1600_get_f_null, keccakF_1600_get_setup,
				keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_start_odd,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_start_gt_width,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_start_eq_width,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_out_null_len_nonzero,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_out_null_len_zero,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_out_nonnull_len_zero,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_start_len_gt_width,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_start_len_eq_width,
				keccakF_1600_get_setup, keccakF_1600_get_teardown),
		unit_test_setup_teardown(keccakF_1600_get_diff_lens,
				keccakF_1600_get_setup, keccakF_1600_get_teardown)
	};

	fprintf(stderr, "keccakF_1600_get:\n");
	res |= run_tests(keccakF_1600_get_tests);
	fprintf(stderr, "\n");

	const UnitTest keccakF_1600_f_tests[] = {
		unit_test_setup_teardown(keccakF_1600_f_f_null, keccakF_1600_f_setup,
				keccakF_1600_f_teardown),
		unit_test_setup_teardown(keccakF_1600_f_all_zero, keccakF_1600_f_setup,
				keccakF_1600_f_teardown),
		unit_test_setup_teardown(keccakF_1600_f_all_one, keccakF_1600_f_setup,
				keccakF_1600_f_teardown),
		unit_test_setup_teardown(keccakF_1600_f_pattern, keccakF_1600_f_setup,
				keccakF_1600_f_teardown)
	};

	fprintf(stderr, "keccakF_1600_f:\n");
	res |= run_tests(keccakF_1600_f_tests);
	fprintf(stderr, "\n");

	const UnitTest keccakPad_10_1_init_tests[] = {
		unit_test(keccakPad_10_1_init_rate_zero),
		unit_test(keccakPad_10_1_init_rate_lt_minrate),
		unit_test(keccakPad_10_1_init_rate_eq_minrate),
		unit_test(keccakPad_10_1_init_rate_odd),
		unit_test(keccakPad_10_1_init_noalloc),
		unit_test(keccakPad_10_1_init_alloc_limited),
		unit_test(keccakPad_10_1_init_normal),
		unit_test(keccakPad_10_1_init_rate_1_left)
	};

	fprintf(stderr, "keccakPad_10_1_init:\n");
	res |= run_tests(keccakPad_10_1_init_tests);
	fprintf(stderr, "\n");

	const UnitTest keccakPad_10_1_pf_tests[] = {
		unit_test_setup_teardown(keccakPad_10_1_pf_p_null,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_f_null,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_p_null_f_null,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_gt_rate,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_eq_rate,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_width_lt_rate,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_width_eq_rate,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_xor_fail,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_f_fail,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_zero,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_even,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_odd,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_2_left,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test_setup_teardown(keccakPad_10_1_pf_remaining_1_left,
				keccakPad_10_1_pf_setup, keccakPad_10_1_pf_teardown),
		unit_test(keccakPad_10_1_pf_diff_rates)
	};

	fprintf(stderr, "keccakPad_10_1_pf:\n");
	res |= run_tests(keccakPad_10_1_pf_tests);
	fprintf(stderr, "\n");

	return res;
}
