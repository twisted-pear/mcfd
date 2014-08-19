#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <crypto_helpers.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define ZEROBUF_SIZE 4096
#define ZEROBUF_PATTERN 0xAA

static unsigned char *zerobuf = NULL;

static void explicit_bzero_setup(void **state __attribute__((unused)))
{
	zerobuf = calloc(ZEROBUF_SIZE, 1);
	assert_non_null(zerobuf);

	memset(zerobuf, ZEROBUF_PATTERN, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], ZEROBUF_PATTERN);
	}
}

static void explicit_bzero_teardown(void **state __attribute__((unused)))
{
	free(zerobuf);
}

static void explicit_bzero_n_zero(void **state __attribute__((unused)))
{
	explicit_bzero(zerobuf, 0);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], ZEROBUF_PATTERN);
	}
}

static void explicit_bzero_s_null_n_zero(void **state __attribute__((unused)))
{
	explicit_bzero(NULL, 0);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], ZEROBUF_PATTERN);
	}
}

static void explicit_bzero_zero(void **state __attribute__((unused)))
{
	memset(zerobuf, 0, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], 0);
	}

	explicit_bzero(zerobuf, ZEROBUF_SIZE);

	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], 0);
	}
}

static void explicit_bzero_normal(void **state __attribute__((unused)))
{
	explicit_bzero(zerobuf, ZEROBUF_SIZE);

	size_t i;
	for (i = 0; i < ZEROBUF_SIZE; i++) {
		assert_int_equal(zerobuf[i], 0);
	}
}

#define CMPBUF_SIZE 4096
#define CMPBUF_LOOP_SIZE 100
#define CMPBUF_PATTERN 0xAA

static unsigned char *cmpbuf1 = NULL;
static unsigned char *cmpbuf2 = NULL;

static void timingsafe_bcmp_setup(void **state __attribute__((unused)))
{
	cmpbuf1 = calloc(CMPBUF_SIZE, 1);
	assert_non_null(cmpbuf1);

	cmpbuf2 = calloc(CMPBUF_SIZE, 1);
	assert_non_null(cmpbuf1);

	memset(cmpbuf1, CMPBUF_PATTERN, CMPBUF_SIZE);
	memset(cmpbuf2, CMPBUF_PATTERN, CMPBUF_SIZE);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_teardown(void **state __attribute__((unused)))
{
	free(cmpbuf1);
	free(cmpbuf2);
}


static void timingsafe_bcmp_n_zero(void **state __attribute__((unused)))
{
	memset(cmpbuf2, ~CMPBUF_PATTERN, CMPBUF_SIZE);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf2[i], (char) ~CMPBUF_PATTERN);
		assert_int_not_equal(cmpbuf1[i], cmpbuf2[i]);
	}

	assert_int_equal(timingsafe_bcmp(cmpbuf1, cmpbuf2, 0), 0);

	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], (char) ~CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_s1_null_n_zero(void **state __attribute__((unused)))
{
	assert_int_equal(timingsafe_bcmp(NULL, cmpbuf2, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_s2_null_n_zero(void **state __attribute__((unused)))
{
	assert_int_equal(timingsafe_bcmp(cmpbuf1, NULL, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_s1_null_s2_null_n_zero(void **state __attribute__((unused)))
{
	assert_int_equal(timingsafe_bcmp(NULL, NULL, 0), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_equal(void **state __attribute__((unused)))
{
	assert_int_equal(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 0);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_not_equal_early(void **state __attribute__((unused)))
{
	cmpbuf1[0] = (char) ~CMPBUF_PATTERN;

	assert_int_equal(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 1);

	assert_int_equal(cmpbuf1[0], (char) ~CMPBUF_PATTERN);
	assert_int_equal(cmpbuf2[0], CMPBUF_PATTERN);

	size_t i;
	for (i = 1; i < CMPBUF_SIZE; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}
}

static void timingsafe_bcmp_not_equal_late(void **state __attribute__((unused)))
{
	cmpbuf1[CMPBUF_SIZE - 1] = (char) ~CMPBUF_PATTERN;

	assert_int_equal(timingsafe_bcmp(cmpbuf1, cmpbuf2, CMPBUF_SIZE), 1);

	size_t i;
	for (i = 0; i < CMPBUF_SIZE - 1; i++) {
		assert_int_equal(cmpbuf1[i], CMPBUF_PATTERN);
		assert_int_equal(cmpbuf2[i], CMPBUF_PATTERN);
	}

	assert_int_equal(cmpbuf1[CMPBUF_SIZE - 1], (char) ~CMPBUF_PATTERN);
	assert_int_equal(cmpbuf2[CMPBUF_SIZE - 1], CMPBUF_PATTERN);
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest explicit_bzero_tests[] = {
		unit_test_setup_teardown(explicit_bzero_n_zero, explicit_bzero_setup,
				explicit_bzero_teardown),
		unit_test_setup_teardown(explicit_bzero_s_null_n_zero,
				explicit_bzero_setup, explicit_bzero_teardown),
		unit_test_setup_teardown(explicit_bzero_zero, explicit_bzero_setup,
				explicit_bzero_teardown),
		unit_test_setup_teardown(explicit_bzero_normal, explicit_bzero_setup,
				explicit_bzero_teardown)
	};

	fprintf(stderr, "explicit_bzero:\n");
	res |= run_tests(explicit_bzero_tests);
	fprintf(stderr, "\n");

	/* TODO: test data independent timing too */
	const UnitTest timingsafe_bcmp_tests[] = {
		unit_test_setup_teardown(timingsafe_bcmp_n_zero, timingsafe_bcmp_setup,
				timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_s1_null_n_zero,
				timingsafe_bcmp_setup, timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_s2_null_n_zero,
				timingsafe_bcmp_setup, timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_s1_null_s2_null_n_zero,
				timingsafe_bcmp_setup, timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_equal, timingsafe_bcmp_setup,
				timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_not_equal_early,
				timingsafe_bcmp_setup, timingsafe_bcmp_teardown),
		unit_test_setup_teardown(timingsafe_bcmp_not_equal_late,
				timingsafe_bcmp_setup, timingsafe_bcmp_teardown)
	};

	fprintf(stderr, "timingsafe_bcmp:\n");
	res |= run_tests(timingsafe_bcmp_tests);
	fprintf(stderr, "\n");

	return res;
}
