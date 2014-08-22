#include <stdlib.h>

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
				sponge_init_teardown)
	};

	fprintf(stderr, "sponge_init:\n");
	res |= run_tests(sponge_init_tests);
	fprintf(stderr, "\n");

	/* TODO: test remaining functionality */

	return res;
}
