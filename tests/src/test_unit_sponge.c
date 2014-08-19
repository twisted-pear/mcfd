#include <stdlib.h>

#include <pad.h>
#include <permutation.h>
#include <sponge.h>

#include <check.h>

#define CREATE_WIDTH 1600
#define CREATE_RATE 1024
#define CREATE_MIN_RATE 2

permutation *f = NULL;
pad *p = NULL;

void sponge_init_setup(void)
{
	f = calloc(1, sizeof(permutation));
	ck_assert_ptr_ne(f, NULL);

	f->width = CREATE_WIDTH;

	p = calloc(1, sizeof(pad));
	ck_assert_ptr_ne(p, NULL);

	p->rate = CREATE_RATE;
	p->min_bit_len = CREATE_MIN_RATE;
}

void sponge_init_teardown(void)
{
	free(f);
	free(p);
}

START_TEST(sponge_init_f_null)
{
	ck_assert_ptr_eq(sponge_init(NULL, p, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_p_null)
{
	ck_assert_ptr_eq(sponge_init(f, NULL, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_rate_zero)
{
	p->rate = 0;
	p->min_bit_len = 0;

	ck_assert_ptr_eq(sponge_init(f, p, 0), NULL);
}
END_TEST

START_TEST(sponge_init_width_zero)
{
	f->width = 0;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_rate_zero_width_zero)
{
	f->width = 0;

	p->rate = 0;
	p->min_bit_len = 0;

	ck_assert_ptr_eq(sponge_init(f, p, 0), NULL);
}
END_TEST

START_TEST(sponge_init_rate_gt_width)
{
	p->rate = CREATE_WIDTH + 8;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_WIDTH + 8), NULL);
}
END_TEST

START_TEST(sponge_init_rate_eq_width)
{
	p->rate = CREATE_WIDTH;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_WIDTH), NULL);
}
END_TEST

START_TEST(sponge_init_rate_ne_prate)
{
	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE + 8), NULL);
}
END_TEST

START_TEST(sponge_init_rate_lt_minrate)
{
	p->min_bit_len = CREATE_RATE + 1;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_rate_eq_minrate)
{
	p->min_bit_len = CREATE_RATE;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_rate_odd)
{
	p->rate = CREATE_RATE + 1;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE + 1), NULL);
}
END_TEST

START_TEST(sponge_init_width_odd)
{
	f->width = CREATE_WIDTH + 1;

	ck_assert_ptr_eq(sponge_init(f, p, CREATE_RATE), NULL);
}
END_TEST

START_TEST(sponge_init_normal)
{
	p->rate = _i * 8;

	sponge *sp = sponge_init(f, p, _i * 8);
	ck_assert_ptr_ne(sp, NULL);

	ck_assert_ptr_eq(sp->f, f);
	ck_assert_ptr_eq(sp->p, p);
	ck_assert_uint_eq(sp->rate, _i * 8);

	sponge_free(sp);
}
END_TEST

Suite *create_test_suite(void)
{
	Suite *s = suite_create("Sponge");

	TCase *tc_sponge_init = tcase_create("sponge_init");
	tcase_add_checked_fixture(tc_sponge_init, sponge_init_setup,
			sponge_init_teardown);
	tcase_add_test(tc_sponge_init, sponge_init_f_null);
	tcase_add_test(tc_sponge_init, sponge_init_p_null);
	tcase_add_test(tc_sponge_init, sponge_init_rate_zero);
	tcase_add_test(tc_sponge_init, sponge_init_width_zero);
	tcase_add_test(tc_sponge_init, sponge_init_rate_zero_width_zero);
	tcase_add_test(tc_sponge_init, sponge_init_rate_gt_width);
	tcase_add_test(tc_sponge_init, sponge_init_rate_eq_width);
	tcase_add_test(tc_sponge_init, sponge_init_rate_ne_prate);
	tcase_add_test(tc_sponge_init, sponge_init_rate_lt_minrate);
	tcase_add_test(tc_sponge_init, sponge_init_rate_eq_minrate);
	tcase_add_test(tc_sponge_init, sponge_init_rate_odd);
	tcase_add_test(tc_sponge_init, sponge_init_width_odd);
	tcase_add_loop_test(tc_sponge_init, sponge_init_normal,
			((CREATE_MIN_RATE + 1) + 7) / 8, (CREATE_WIDTH) / 8);
	suite_add_tcase(s, tc_sponge_init);

	/* TODO: test remaining sponge functionality */

	return s;
}
