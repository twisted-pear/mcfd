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

#define XOR_TEST_PATTERN 0xAA
#define GET_TEST_PATTERN 0x55
#define F_TEST_PATTERN 0xA5

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

	memset(testbuf, XOR_TEST_PATTERN, EXPECTED_WIDTH / 8);

	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], XOR_TEST_PATTERN);
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

		memset(testbuf, XOR_TEST_PATTERN, EXPECTED_WIDTH / 8);
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
		assert_int_equal(testbuf[i], XOR_TEST_PATTERN);
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
			assert_int_equal(testbuf[i], XOR_TEST_PATTERN);
		}
		if (len % 8 != 0) {
			assert_int_equal(testbuf[i], XOR_TEST_PATTERN >> (8 - (len % 8)));
			i++;
		}
		for (; i < EXPECTED_WIDTH / 8; i++) {
			assert_int_equal(testbuf[i], 0);
		}

		memset(testbuf, XOR_TEST_PATTERN, EXPECTED_WIDTH / 8);
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
	f = keccakF_1600_init();
	assert_non_null(f);

	assert_true(f->width == EXPECTED_WIDTH);
	assert_non_null(f->f);
	assert_non_null(f->xor);
	assert_non_null(f->get);

	testbuf = calloc(EXPECTED_WIDTH / 8, 1);
	assert_non_null(testbuf);
}

static void keccakF_1600_f_teardown(void **state __attribute__((unused)))
{
	keccakF_1600_free(f);
	free(testbuf);
}

static void keccakF_1600_f_f_null(void **state __attribute__((unused)))
{
	memset(testbuf, F_TEST_PATTERN, EXPECTED_WIDTH / 8);
	assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);

	assert_int_equal(f->f(NULL), 1);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], F_TEST_PATTERN);
	}
}

static const unsigned char f_zero_expected[EXPECTED_WIDTH / 8] = {
	0xe7, 0xdd, 0xe1, 0x40, 0x79, 0x8f, 0x25, 0xf1, 0x8a, 0x47, 0xc0, 0x33, 0xf9,
	0xcc, 0xd5, 0x84, 0xee, 0xa9, 0x5a, 0xa6, 0x1e, 0x26, 0x98, 0xd5, 0x4d, 0x49,
	0x80, 0x6f, 0x30, 0x47, 0x15, 0xbd, 0x57, 0xd0, 0x53, 0x62, 0x05, 0x4e, 0x28,
	0x8b, 0xd4, 0x6f, 0x8e, 0x7f, 0x2d, 0xa4, 0x97, 0xff, 0xc4, 0x47, 0x46, 0xa4,
	0xa0, 0xe5, 0xfe, 0x90, 0x76, 0x2e, 0x19, 0xd6, 0x0c, 0xda, 0x5b, 0x8c, 0x9c,
	0x05, 0x19, 0x1b, 0xf7, 0xa6, 0x30, 0xad, 0x64, 0xfc, 0x8f, 0xd0, 0xb7, 0x5a,
	0x93, 0x30, 0x35, 0xd6, 0x17, 0x23, 0x3f, 0xa9, 0x5a, 0xeb, 0x03, 0x21, 0x71,
	0x0d, 0x26, 0xe6, 0xa6, 0xa9, 0x5f, 0x55, 0xcf, 0xdb, 0x16, 0x7c, 0xa5, 0x81,
	0x26, 0xc8, 0x47, 0x03, 0xcd, 0x31, 0xb8, 0x43, 0x9f, 0x56, 0xa5, 0x11, 0x1a,
	0x2f, 0xf2, 0x01, 0x61, 0xae, 0xd9, 0x21, 0x5a, 0x63, 0xe5, 0x05, 0xf2, 0x70,
	0xc9, 0x8c, 0xf2, 0xfe, 0xbe, 0x64, 0x11, 0x66, 0xc4, 0x7b, 0x95, 0x70, 0x36,
	0x61, 0xcb, 0x0e, 0xd0, 0x4f, 0x55, 0x5a, 0x7c, 0xb8, 0xc8, 0x32, 0xcf, 0x1c,
	0x8a, 0xe8, 0x3e, 0x8c, 0x14, 0x26, 0x3a, 0xae, 0x22, 0x79, 0x0c, 0x94, 0xe4,
	0x09, 0xc5, 0xa2, 0x24, 0xf9, 0x41, 0x18, 0xc2, 0x65, 0x04, 0xe7, 0x26, 0x35,
	0xf5, 0x16, 0x3b, 0xa1, 0x30, 0x7f, 0xe9, 0x44, 0xf6, 0x75, 0x49, 0xa2, 0xec,
	0x5c, 0x7b, 0xff, 0xf1, 0xea
};

static void keccakF_1600_f_all_zero(void **state __attribute__((unused)))
{
	memset(testbuf, 0, EXPECTED_WIDTH / 8);
	assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);

	assert_int_equal(f->f(f), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], f_zero_expected[i]);
	}
}

static const unsigned char f_one_expected[EXPECTED_WIDTH / 8] = {
	0xc4, 0x17, 0x68, 0xba, 0x1b, 0xf2, 0x00, 0x9f, 0x78, 0x5e, 0xaf, 0x21, 0x0d,
	0xaa, 0xf5, 0xcd, 0x97, 0x5b, 0x09, 0x24, 0xbf, 0x9a, 0x53, 0xd6, 0x28, 0x82,
	0x0f, 0x01, 0x0a, 0xf3, 0xb6, 0x8b, 0x1d, 0x33, 0x47, 0x05, 0xba, 0x11, 0xf7,
	0xf0, 0x2f, 0x18, 0xeb, 0x58, 0x05, 0x33, 0x44, 0x4f, 0x7c, 0x20, 0x55, 0x90,
	0x9d, 0xb7, 0x13, 0x22, 0x90, 0xb4, 0x4f, 0xca, 0x55, 0x5b, 0x5e, 0xeb, 0xd4,
	0xb5, 0x99, 0xa2, 0x81, 0xeb, 0xfa, 0x0b, 0x48, 0xed, 0x65, 0x1a, 0x4f, 0x92,
	0x5d, 0x9e, 0xb3, 0xbf, 0xb7, 0x33, 0xc5, 0x50, 0x46, 0x00, 0x05, 0xab, 0xd7,
	0x84, 0x4b, 0x45, 0xad, 0xdd, 0x21, 0x29, 0xe8, 0x03, 0x65, 0xe5, 0x3c, 0xf0,
	0x60, 0x86, 0x72, 0xc6, 0x92, 0x2e, 0x44, 0xce, 0xd3, 0xdc, 0x7d, 0xb3, 0xe4,
	0xe5, 0x9c, 0x1a, 0x0e, 0x6f, 0xea, 0x7c, 0xe2, 0x60, 0x3b, 0xf6, 0xad, 0xbf,
	0x65, 0xa6, 0xfc, 0xc7, 0x4c, 0xcc, 0x5d, 0x28, 0xa2, 0x54, 0xba, 0x4e, 0xcf,
	0x40, 0x13, 0x42, 0x30, 0x42, 0xf1, 0xf1, 0x25, 0x27, 0x9b, 0xad, 0xfb, 0xe6,
	0x7d, 0x32, 0x4d, 0x55, 0xc2, 0xbd, 0xc8, 0xcb, 0x26, 0x6a, 0x86, 0x19, 0xf5,
	0xc7, 0x02, 0xaf, 0x8f, 0xc2, 0xc3, 0xe8, 0xae, 0x65, 0xa6, 0x12, 0x35, 0x1f,
	0xbc, 0xc6, 0xce, 0x86, 0xdc, 0xa5, 0xf1, 0x31, 0xa8, 0xca, 0xb0, 0xb9, 0xa4,
	0x1c, 0xe9, 0xaf, 0x82, 0x3f
};

static void keccakF_1600_f_all_one(void **state __attribute__((unused)))
{
	memset(testbuf, 0xFF, EXPECTED_WIDTH / 8);
	assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);

	assert_int_equal(f->f(f), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], f_one_expected[i]);
	}
}

static const unsigned char f_pattern_expected[EXPECTED_WIDTH / 8] = {
	0xaf, 0x5b, 0x94, 0x69, 0x62, 0x7d, 0xf8, 0x40, 0x4a, 0xef, 0x62, 0x0c, 0x23,
	0x7a, 0x7d, 0x24, 0x5c, 0x6b, 0x08, 0x53, 0xb6, 0x98, 0x8d, 0xcb, 0xe6, 0x80,
	0x6d, 0xeb, 0xa3, 0x39, 0xb4, 0x14, 0x99, 0xbb, 0xa3, 0x60, 0x4d, 0xc8, 0xae,
	0x7a, 0x3c, 0xc9, 0x4b, 0xf5, 0x9f, 0x52, 0x6f, 0xfb, 0x4b, 0x8a, 0xdf, 0xee,
	0x84, 0xd8, 0xef, 0x9b, 0x77, 0x25, 0xec, 0x9e, 0x4d, 0x40, 0xe0, 0xab, 0x96,
	0xec, 0xd4, 0x7c, 0x2d, 0xde, 0x26, 0x6d, 0x43, 0x0b, 0x3f, 0xfa, 0x8c, 0x0f,
	0x5c, 0xe0, 0x42, 0xbc, 0x0c, 0xed, 0x47, 0xc3, 0xc7, 0x0f, 0x6d, 0x8d, 0xae,
	0xad, 0x81, 0x44, 0xcb, 0x67, 0xfc, 0xc5, 0xf3, 0x9d, 0xe9, 0x83, 0x73, 0xbf,
	0x12, 0x28, 0x77, 0x12, 0xc7, 0xc3, 0x16, 0xa2, 0x51, 0x3b, 0x2f, 0x4e, 0xe8,
	0xd3, 0x10, 0xc7, 0x63, 0xb0, 0x10, 0xdf, 0xe3, 0x65, 0xe5, 0xb5, 0xb0, 0x7f,
	0x92, 0xc2, 0xf2, 0xbc, 0x52, 0x77, 0x59, 0x12, 0x9c, 0x8d, 0x01, 0x73, 0xb5,
	0x23, 0xca, 0x77, 0xe0, 0x7b, 0xea, 0x31, 0x60, 0x35, 0xcf, 0xda, 0x83, 0x9c,
	0x77, 0x83, 0xf8, 0x63, 0x36, 0xa2, 0xfe, 0xf0, 0x58, 0x49, 0xb0, 0x00, 0xb8,
	0x76, 0x10, 0xcd, 0x28, 0x6b, 0x1e, 0x2b, 0xed, 0x00, 0x9f, 0x18, 0x8b, 0x63,
	0x93, 0x97, 0xde, 0xab, 0x9d, 0xbb, 0x4c, 0x53, 0x0c, 0xe3, 0x04, 0x95, 0xc3,
	0x2d, 0xcd, 0x70, 0x27, 0xa2
};

static void keccakF_1600_f_pattern(void **state __attribute__((unused)))
{
	memset(testbuf, F_TEST_PATTERN, EXPECTED_WIDTH / 8);
	assert_int_equal(f->xor(f, 0, testbuf, EXPECTED_WIDTH), 0);

	assert_int_equal(f->f(f), 0);

	assert_int_equal(f->get(f, 0, testbuf, EXPECTED_WIDTH), 0);
	size_t i;
	for (i = 0; i < EXPECTED_WIDTH / 8; i++) {
		assert_int_equal(testbuf[i], f_pattern_expected[i]);
	}
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
