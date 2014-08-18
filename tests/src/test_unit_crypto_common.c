#include <limits.h>
#include <stdlib.h>

#include <crypto_helpers.h>

#include <check.h>

#define ZEROBUF_SIZE 4096
#define ZEROBUF_PATTERN 0xAA

static unsigned char *zerobuf = NULL;

static void explicit_bzero_setup(void)
{
	zerobuf = calloc(ZEROBUF_SIZE, 1);
	ck_assert_ptr_ne(zerobuf, NULL);

	memset(zerobuf, ZEROBUF_PATTERN, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], ZEROBUF_PATTERN);
	}
}

static void explicit_bzero_teardown(void)
{
	free(zerobuf);
}

START_TEST(explicit_bzero_n_zero)
{
	explicit_bzero(zerobuf, 0);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], ZEROBUF_PATTERN);
	}
}
END_TEST

START_TEST(explicit_bzero_s_null_n_zero)
{
	explicit_bzero(NULL, 0);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], ZEROBUF_PATTERN);
	}
}
END_TEST

START_TEST(explicit_bzero_zero)
{
	memset(zerobuf, 0, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], 0);
	}

	explicit_bzero(zerobuf, ZEROBUF_SIZE);

	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], 0);
	}
}
END_TEST

START_TEST(explicit_bzero_normal)
{
	explicit_bzero(zerobuf, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		ck_assert_int_eq(zerobuf[i], 0);
	}
}
END_TEST

#define CMPBUF_SIZE 4096
#define CMPBUF_LOOP_SIZE 100
#define CMPBUF_PATTERN 0xAA

static unsigned char *cmpbuf1 = NULL;
static unsigned char *cmpbuf2 = NULL;

static void timingsafe_bcmp_setup(void)
{
	cmpbuf1 = calloc(CMPBUF_SIZE, 1);
	ck_assert_ptr_ne(cmpbuf1, NULL);

	cmpbuf2 = calloc(CMPBUF_SIZE, 1);
	ck_assert_ptr_ne(cmpbuf1, NULL);

	memset(cmpbuf1, CMPBUF_PATTERN, CMPBUF_SIZE);
	memset(cmpbuf2, CMPBUF_PATTERN, CMPBUF_SIZE);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_teardown(void)
{
	free(cmpbuf1);
	free(cmpbuf2);
}


START_TEST(timingsafe_bcmp_n_zero)
{
	memset(cmpbuf2, ~CMPBUF_PATTERN, CMPBUF_SIZE);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf2[i], (char) ~CMPBUF_PATTERN);
		ck_assert_int_ne(cmpbuf1[i], cmpbuf2[i]);
	}

	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, cmpbuf2, 0), 0);

	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], (char) ~CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_s1_null_n_zero)
{
	ck_assert_int_eq(timingsafe_bcmp(NULL, cmpbuf2, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_s2_null_n_zero)
{
	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, NULL, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_s1_null_s2_null_n_zero)
{
	ck_assert_int_eq(timingsafe_bcmp(NULL, NULL, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_equal)
{
	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_not_equal)
{
	ck_assert_uint_ge(_i, 0);
	ck_assert_uint_le(_i, INT_MAX);

	cmpbuf1[_i] = (char) ~CMPBUF_PATTERN;

	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_LOOP_SIZE), 1);

	size_t i;
	for (i = 1; i < CMPBUF_LOOP_SIZE; i++) {
		if (i == (size_t) _i) {
			ck_assert_int_eq(cmpbuf1[i], (char) ~CMPBUF_PATTERN);
		} else {
			ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		}

		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_not_equal_early)
{
	cmpbuf1[0] = (char) ~CMPBUF_PATTERN;

	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 1);

	ck_assert_int_eq(cmpbuf1[0], (char) ~CMPBUF_PATTERN);
	ck_assert_int_eq(cmpbuf2[0], CMPBUF_PATTERN);

	size_t i;
	for (i = 1; i < CMPBUF_SIZE; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}
}
END_TEST

START_TEST(timingsafe_bcmp_not_equal_late)
{
	cmpbuf1[CMPBUF_SIZE - 1] = (char) ~CMPBUF_PATTERN;

	ck_assert_int_eq(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 1);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE - 1; i++) {
		ck_assert_int_eq(cmpbuf1[i], CMPBUF_PATTERN);
		ck_assert_int_eq(cmpbuf2[i], CMPBUF_PATTERN);
	}

	ck_assert_int_eq(cmpbuf1[CMPBUF_SIZE - 1], (char) ~CMPBUF_PATTERN);
	ck_assert_int_eq(cmpbuf2[CMPBUF_SIZE - 1], CMPBUF_PATTERN);
}
END_TEST

Suite *create_test_suite(void)
{
	Suite *s = suite_create("Crypto Helpers");

	TCase *tc_explicit_bzero = tcase_create("explicit_bzero");
	tcase_add_checked_fixture(tc_explicit_bzero, explicit_bzero_setup,
			explicit_bzero_teardown);
	tcase_add_test(tc_explicit_bzero, explicit_bzero_n_zero);
	tcase_add_test(tc_explicit_bzero, explicit_bzero_s_null_n_zero);
	tcase_add_test(tc_explicit_bzero, explicit_bzero_zero);
	tcase_add_test(tc_explicit_bzero, explicit_bzero_normal);
	suite_add_tcase(s, tc_explicit_bzero);

	/* TODO: test data independent timing too */
	TCase *tc_timingsafe_bcmp = tcase_create("timingsafe_bcmp");
	tcase_add_checked_fixture(tc_timingsafe_bcmp, timingsafe_bcmp_setup,
			timingsafe_bcmp_teardown);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_n_zero);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_s1_null_n_zero);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_s2_null_n_zero);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_s1_null_s2_null_n_zero);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_equal);
	tcase_add_loop_test(tc_timingsafe_bcmp, timingsafe_bcmp_not_equal, 0,
			CMPBUF_LOOP_SIZE);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_not_equal_early);
	tcase_add_test(tc_timingsafe_bcmp, timingsafe_bcmp_not_equal_late);
	suite_add_tcase(s, tc_timingsafe_bcmp);

	return s;
}
