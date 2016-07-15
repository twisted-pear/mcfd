#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sponge.h"
#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>
#include <mcfd_kdf.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define PERM_WIDTH 1600
#define RATE 576
#define PAD_MIN_LEN 2

#define KEY_BITS 256
#define KEY_PATTERN 0xA0

#define ITERATIONS MCFD_KDF_DEF_ITERATIONS

#define PASS_LEN 64
#define PASS_PATTERN 0x66

#define SALT_LEN MCFD_SALT_BYTES
#define SALT_PATTERN 0x5A

#define SQUEEZE_PATTERN 0x05

permutation *keccakF_1600_init(void)
{
	return mock_ptr_type(permutation *);
}

void keccakF_1600_free(permutation *p)
{
	check_expected(p);
}

pad *keccakPad_10_1_init(const size_t rate)
{
	check_expected(rate);

	return mock_ptr_type(pad *);
}

void keccakPad_10_1_free(pad *p)
{
	check_expected(p);
}

sponge *sponge_init(permutation *f, pad *p, const size_t rate)
{
	check_expected(f);
	check_expected(p);
	check_expected(rate);

	return mock_ptr_type(sponge *);
}

void sponge_free(sponge *sp)
{
	check_expected(sp);
}

constr_result sponge_absorb(sponge *sp, const unsigned char *input,
		const size_t input_bit_len)
{
	check_expected(sp);
	check_expected(input);
	check_expected(input_bit_len);

	return mock_type(constr_result);
}

constr_result sponge_absorb_final(sponge *sp)
{
	check_expected(sp);

	return mock_type(constr_result);
}

constr_result sponge_squeeze(sponge *sp, unsigned char *output,
		const size_t output_bit_len)
{
	check_expected(sp);
	check_expected(output);
	check_expected(output_bit_len);

	memset(output, SQUEEZE_PATTERN, (output_bit_len + 7) / 8);

	return mock_type(constr_result);
}

static char *pass;
static unsigned char *salt;
static unsigned char *key;

static permutation *f;
static pad *p;
static sponge *sp;

static int order = 0;

static int mcfd_kdf_setup(void **state __attribute__((unused)))
{
	pass = calloc(PASS_LEN, 1);
	assert_non_null(pass);
	memset(pass, PASS_PATTERN, PASS_LEN);

	salt = calloc(SALT_LEN, 1);
	assert_non_null(salt);
	memset(salt, SALT_PATTERN, SALT_LEN);

	key = calloc((KEY_BITS + 7) / 8, 1);
	assert_non_null(key);
	memset(key, KEY_PATTERN, (KEY_BITS + 7) / 8);

	f = calloc(1, sizeof(permutation));
	assert_non_null(f);
	f->width = PERM_WIDTH;
	f->internal = &order;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);
	p->rate = RATE;
	p->min_bit_len = PAD_MIN_LEN;
	p->internal = &order;

	sp = calloc(1, sizeof(sponge));
	assert_non_null(sp);
	sp->f = f;
	sp->p = p;
	sp->rate = RATE;
	sp->internal = &order;

	return 0;
}

static int mcfd_kdf_teardown(void **state __attribute__((unused)))
{
	size_t i;
	for (i = 0; i < PASS_LEN; i++) {
		assert_int_equal(pass[i], PASS_PATTERN);
	}
	for (i = 0; i < SALT_LEN; i++) {
		assert_int_equal(salt[i], SALT_PATTERN);
	}

	free(pass);
	free(salt);
	free(key);

	free(f);
	free(p);
	free(sp);

	return 0;
}

static void mcfd_kdf_success(size_t pass_len, bool use_salt, size_t iterations,
		size_t key_bits)
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, pass_len * 8);
	will_return(sponge_absorb, 0);

	if (use_salt) {
		expect_value(sponge_absorb, sp, sp);
		expect_value(sponge_absorb, input, salt);
		expect_value(sponge_absorb, input_bit_len, SALT_LEN * 8);
		will_return(sponge_absorb, 0);
	}

	expect_value(sponge_absorb_final, sp, sp);
	will_return(sponge_absorb_final, 0);

	expect_value_count(sponge_squeeze, sp, sp, iterations - 1);
	expect_any_count(sponge_squeeze, output, iterations - 1);
	expect_value_count(sponge_squeeze, output_bit_len, RATE, iterations - 1);
	will_return_count(sponge_squeeze, 0, iterations - 1);

	expect_value(sponge_squeeze, sp, sp);
	expect_value(sponge_squeeze, output, key);
	expect_value(sponge_squeeze, output_bit_len, key_bits);
	will_return(sponge_squeeze, 0);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);
}

static void mcfd_kdf_pass_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_kdf(NULL, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_plen_zero(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_kdf(pass, 0, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_salt_null(void **state __attribute__((unused)))
{
	mcfd_kdf_success(PASS_LEN, false, ITERATIONS, KEY_BITS);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, NULL, ITERATIONS, key, KEY_BITS), 0);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], SQUEEZE_PATTERN);
	}
}

static void mcfd_kdf_iter_zero(void **state __attribute__((unused)))
{
	mcfd_kdf_success(PASS_LEN, true, ITERATIONS, KEY_BITS);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, 0, key, KEY_BITS), 0);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], SQUEEZE_PATTERN);
	}
}

static void mcfd_kdf_key_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, NULL, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_kbits_zero(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, 0), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_kbits_odd(void **state __attribute__((unused)))
{
	mcfd_kdf_success(PASS_LEN, true, ITERATIONS, 3);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, 3), 0);

	size_t i;
	assert_int_equal(key[0], SQUEEZE_PATTERN);
	for (i = 1; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_f_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, NULL);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_p_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, NULL);

	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_sp_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, NULL);

	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_absorb_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, PASS_LEN * 8);
	will_return(sponge_absorb, 1);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
	for (i = 0; i < PASS_LEN; i++) {
		assert_int_equal(pass[i], PASS_PATTERN);
	}
	for (i = 0; i < SALT_LEN; i++) {
		assert_int_equal(salt[i], SALT_PATTERN);
	}

	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, PASS_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, salt);
	expect_value(sponge_absorb, input_bit_len, SALT_LEN * 8);
	will_return(sponge_absorb, 1);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_absorb_final_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, PASS_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, salt);
	expect_value(sponge_absorb, input_bit_len, SALT_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb_final, sp, sp);
	will_return(sponge_absorb_final, 1);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
}

static void mcfd_kdf_squeeze_fail(void **state __attribute__((unused)))
{

	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, PASS_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, salt);
	expect_value(sponge_absorb, input_bit_len, SALT_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb_final, sp, sp);
	will_return(sponge_absorb_final, 0);

	expect_value_count(sponge_squeeze, sp, sp, ITERATIONS - 2);
	expect_any_count(sponge_squeeze, output, ITERATIONS - 2);
	expect_value_count(sponge_squeeze, output_bit_len, RATE, ITERATIONS - 2);
	will_return_count(sponge_squeeze, 0, ITERATIONS - 2);

	expect_value(sponge_squeeze, sp, sp);
	expect_any(sponge_squeeze, output);
	expect_value(sponge_squeeze, output_bit_len, RATE);
	will_return(sponge_squeeze, 1);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
	for (i = 0; i < PASS_LEN; i++) {
		assert_int_equal(pass[i], PASS_PATTERN);
	}
	for (i = 0; i < SALT_LEN; i++) {
		assert_int_equal(salt[i], SALT_PATTERN);
	}

	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(sponge_init, f, f);
	expect_value(sponge_init, p, p);
	expect_value(sponge_init, rate, RATE);
	will_return(sponge_init, sp);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, pass);
	expect_value(sponge_absorb, input_bit_len, PASS_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb, sp, sp);
	expect_value(sponge_absorb, input, salt);
	expect_value(sponge_absorb, input_bit_len, SALT_LEN * 8);
	will_return(sponge_absorb, 0);

	expect_value(sponge_absorb_final, sp, sp);
	will_return(sponge_absorb_final, 0);

	expect_value_count(sponge_squeeze, sp, sp, ITERATIONS - 1);
	expect_any_count(sponge_squeeze, output, ITERATIONS - 1);
	expect_value_count(sponge_squeeze, output_bit_len, RATE, ITERATIONS - 1);
	will_return_count(sponge_squeeze, 0, ITERATIONS - 1);

	expect_value(sponge_squeeze, sp, sp);
	expect_value(sponge_squeeze, output, key);
	expect_value(sponge_squeeze, output_bit_len, KEY_BITS);
	will_return(sponge_squeeze, 1);

	expect_value(sponge_free, sp, sp);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 1);

	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], 0);
	}
}

static void mcfd_kdf_normal(void **state __attribute__((unused)))
{
	mcfd_kdf_success(PASS_LEN, true, ITERATIONS, KEY_BITS);

	assert_int_equal(mcfd_kdf(pass, PASS_LEN, salt, ITERATIONS, key, KEY_BITS), 0);

	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], SQUEEZE_PATTERN);
	}
}

int run_unit_tests(void)
{
	int res = 0;

	const struct CMUnitTest mcfd_kdf_tests[] = {
		cmocka_unit_test_setup_teardown(mcfd_kdf_pass_null,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_plen_zero,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_salt_null,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_iter_zero,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_key_null,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_kbits_zero,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_kbits_odd,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_f_init_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_p_init_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_sp_init_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_absorb_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_absorb_final_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_squeeze_fail,
				mcfd_kdf_setup, mcfd_kdf_teardown),
		cmocka_unit_test_setup_teardown(mcfd_kdf_normal,
				mcfd_kdf_setup, mcfd_kdf_teardown)
	};

	fprintf(stderr, "mcfd_kdf:\n");
	res |= cmocka_run_group_tests(mcfd_kdf_tests, NULL, NULL);
	fprintf(stderr, "\n");

	return res;
}
