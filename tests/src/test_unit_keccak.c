#include <stdlib.h>

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

#define CREATE_RATE 1024
#define CREATE_MAX_ALLOC_SIZE ((EXPECTED_WIDTH / 8) * 2)
#define CREATE_MAX_ALLOCS 10

#define EXPECTED_WIDTH 1600
#define EXPECTED_MIN_PAD_SIZE 2

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

	const UnitTest keccakPad_10_1_init_tests[] = {
		unit_test(keccakPad_10_1_init_rate_zero),
		unit_test(keccakPad_10_1_init_rate_lt_minrate),
		unit_test(keccakPad_10_1_init_rate_eq_minrate),
		unit_test(keccakPad_10_1_init_rate_odd),
		unit_test(keccakPad_10_1_init_noalloc),
		unit_test(keccakPad_10_1_init_alloc_limited),
		unit_test(keccakPad_10_1_init_normal)
	};

	fprintf(stderr, "keccakPad_10_1_init:\n");
	res |= run_tests(keccakPad_10_1_init_tests);
	fprintf(stderr, "\n");

	/* TODO: test remaining functionality */

	return res;
}
