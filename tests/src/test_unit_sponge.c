#include <stdlib.h>

#include <pad.h>
#include <permutation.h>
#include <sponge.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define CREATE_WIDTH 1600
#define CREATE_RATE 1024
#define CREATE_MIN_RATE 2

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

static void sponge_init_normal(void **state __attribute__((unused)))
{
	sponge *sp = sponge_init(f, p, CREATE_RATE);
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
		unit_test_setup_teardown(sponge_init_normal, sponge_init_setup,
				sponge_init_teardown)
	};

	fprintf(stderr, "sponge_init:\n");
	res |= run_tests(sponge_init_tests);
	fprintf(stderr, "\n");

	/* TODO: test remaining functionality */

	return res;
}
