#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "spongewrap.h"
#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>
#include <mcfd_cipher.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_MAX_ALLOC_SIZE 256
#define CREATE_MAX_ALLOCS 10

#define PERM_WIDTH 1600
#define RATE MCFD_BLOCK_SIZE + 8
#define BLOCK_SIZE MCFD_BLOCK_SIZE
#define PAD_MIN_LEN 2

#define KEY_BITS MCFD_KEY_BITS
#define KEY_PATTERN 0x80

#define NONCE_BITS MCFD_NONCE_BITS
#define NONCE_PATTERN 0xD0

#define WRAP_C_PATTERN 0x0C
#define WRAP_T_PATTERN 0x07

#define UNWRAP_B_PATTERN 0x0B

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

spongewrap *spongewrap_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size, const unsigned char *key,
		const size_t key_byte_len)
{
	check_expected(f);
	check_expected(p);
	check_expected(rate);
	check_expected(block_size);
	check_expected(key);
	check_expected(key_byte_len);

	return mock_ptr_type(spongewrap *);
}

void spongewrap_free(spongewrap *w)
{
	check_expected(w);
}

constr_result spongewrap_wrap(spongewrap *w, const unsigned char *a,
		const size_t a_byte_len, const unsigned char *b, const size_t b_byte_len,
		unsigned char *c, unsigned char *t, const size_t t_byte_len)
{
	check_expected(w);
	check_expected(a);
	check_expected(a_byte_len);
	check_expected(b);
	check_expected(b_byte_len);
	check_expected(c);
	check_expected(t);
	check_expected(t_byte_len);

	memset(c, WRAP_C_PATTERN, b_byte_len);
	memset(t, WRAP_T_PATTERN, t_byte_len);

	return mock_type(constr_result);
}

constr_result spongewrap_unwrap(spongewrap *w, const unsigned char *a,
		const size_t a_byte_len, const unsigned char *c, const size_t c_byte_len,
		const unsigned char *t, const size_t t_byte_len, unsigned char *b)
{
	check_expected(w);
	check_expected(a);
	check_expected(a_byte_len);
	check_expected(c);
	check_expected(c_byte_len);
	check_expected(t);
	check_expected(t_byte_len);
	check_expected(b);

	memset(b, UNWRAP_B_PATTERN, c_byte_len);

	return mock_type(constr_result);
}

static unsigned char *key;
static unsigned char *init_nonce;

static permutation *f;
static pad *p;
static spongewrap *w;

static int order = 0;

static int mcfd_cipher_init_setup(void **state __attribute__((unused)))
{
	key = calloc((KEY_BITS + 7) / 8, 1);
	assert_non_null(key);
	memset(key, KEY_PATTERN, (KEY_BITS + 7) / 8);

	init_nonce = calloc((NONCE_BITS + 7) / 8, 1);
	assert_non_null(init_nonce);
	memset(init_nonce, NONCE_PATTERN, (NONCE_BITS + 7) / 8);

	f = calloc(1, sizeof(permutation));
	assert_non_null(f);
	f->width = PERM_WIDTH;
	f->internal = &order;

	p = calloc(1, sizeof(pad));
	assert_non_null(p);
	p->rate = RATE;
	p->min_bit_len = PAD_MIN_LEN;
	p->internal = &order;

	w = calloc(1, sizeof(spongewrap));
	assert_non_null(w);
	w->f = f;
	w->p = p;
	w->rate = RATE;
	w->block_size = BLOCK_SIZE;
	w->internal = &order;

	return 0;
}

static int mcfd_cipher_init_teardown(void **state __attribute__((unused)))
{
	size_t i;
	for (i = 0; i < (KEY_BITS + 7) / 8; i++) {
		assert_int_equal(key[i], KEY_PATTERN);
	}
	for (i = 0; i < (NONCE_BITS + 7) / 8; i++) {
		assert_int_equal(init_nonce[i], NONCE_PATTERN);
	}

	free(key);
	free(init_nonce);

	free(f);
	free(p);
	free(w);

	return 0;
}

static void mcfd_cipher_init_success(void)
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(spongewrap_init, f, f);
	expect_value(spongewrap_init, p, p);
	expect_value(spongewrap_init, rate, RATE);
	expect_value(spongewrap_init, block_size, BLOCK_SIZE / 8);
	expect_value(spongewrap_init, key, key);
	expect_value(spongewrap_init, key_byte_len, KEY_BITS / 8);
	will_return(spongewrap_init, w);
}

static void mcfd_cipher_free_success(void)
{
	expect_value(spongewrap_free, w, w);
	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);
}

static void mcfd_cipher_init_key_null(void **state __attribute__((unused)))
{
	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, NULL);
	assert_null(cipher);
}

static void mcfd_cipher_init_nonce_null(void **state __attribute__((unused)))
{
	mcfd_cipher_init_success();

	mcfd_cipher *cipher = mcfd_cipher_init(NULL, key);
	assert_non_null(cipher);

	mcfd_cipher_free_success();

	mcfd_cipher_free(cipher);
}

static void mcfd_cipher_init_f_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, NULL);

	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, key);
	assert_null(cipher);
}

static void mcfd_cipher_init_p_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, NULL);

	expect_value(keccakF_1600_free, p, f);

	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, key);
	assert_null(cipher);
}

static void mcfd_cipher_init_w_init_fail(void **state __attribute__((unused)))
{
	will_return(keccakF_1600_init, f);

	expect_value(keccakPad_10_1_init, rate, RATE);
	will_return(keccakPad_10_1_init, p);

	expect_value(spongewrap_init, f, f);
	expect_value(spongewrap_init, p, p);
	expect_value(spongewrap_init, rate, RATE);
	expect_value(spongewrap_init, block_size, BLOCK_SIZE / 8);
	expect_value(spongewrap_init, key, key);
	expect_value(spongewrap_init, key_byte_len, KEY_BITS / 8);
	will_return(spongewrap_init, NULL);

	expect_value(keccakPad_10_1_free, p, p);
	expect_value(keccakF_1600_free, p, f);

	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, key);
	assert_null(cipher);
}

static void mcfd_cipher_init_noalloc(void **state __attribute__((unused)))
{
	mcfd_cipher_init_success();
	mcfd_cipher_free_success();

	/* mcfd_cipher_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, key);

	__activate_wrap_alloc = 0;

	assert_null(cipher);
}

static void mcfd_cipher_init_alloc_limited(void **state __attribute__((unused)))
{
	mcfd_cipher_init_success();
	mcfd_cipher_free_success();

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	mcfd_cipher *cipher = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		cipher = mcfd_cipher_init(init_nonce, key);
		if (cipher != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;

		mcfd_cipher_init_success();
		mcfd_cipher_free_success();
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(cipher);

	mcfd_cipher_free(cipher);
}

static void mcfd_cipher_init_normal(void **state __attribute__((unused)))
{
	mcfd_cipher_init_success();

	mcfd_cipher *cipher = mcfd_cipher_init(init_nonce, key);
	assert_non_null(cipher);

	mcfd_cipher_free_success();

	mcfd_cipher_free(cipher);
}

mcfd_cipher *cipher;

static int mcfd_cipher_setup(void **state __attribute__((unused)))
{
	mcfd_cipher_init_setup(state);

	mcfd_cipher_init_success();

	cipher = mcfd_cipher_init(init_nonce, key);
	assert_non_null(cipher);

	return 0;
}

static int mcfd_cipher_teardown(void **state __attribute__((unused)))
{
	mcfd_cipher_free_success();

	mcfd_cipher_free(cipher);

	mcfd_cipher_init_teardown(state);

	return 0;
}

static void mcfd_cipher_encrypt_normal(void **state __attribute__((unused)))
{
}

static void mcfd_cipher_decrypt_normal(void **state __attribute__((unused)))
{
}

int run_unit_tests(void)
{
	int res = 0;

	const struct CMUnitTest mcfd_cipher_init_tests[] = {
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_key_null,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_nonce_null,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_f_init_fail,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_p_init_fail,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_w_init_fail,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_noalloc,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_alloc_limited,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown),
		cmocka_unit_test_setup_teardown(mcfd_cipher_init_normal,
				mcfd_cipher_init_setup, mcfd_cipher_init_teardown)
	};

	fprintf(stderr, "mcfd_cipher_init:\n");
	res |= cmocka_run_group_tests(mcfd_cipher_init_tests, NULL, NULL);
	fprintf(stderr, "\n");

	const struct CMUnitTest mcfd_cipher_encrypt_tests[] = {
		cmocka_unit_test_setup_teardown(mcfd_cipher_encrypt_normal,
				mcfd_cipher_setup, mcfd_cipher_teardown)
	};

	fprintf(stderr, "mcfd_cipher_encrypt:\n");
	res |= cmocka_run_group_tests(mcfd_cipher_encrypt_tests, NULL, NULL);
	fprintf(stderr, "\n");

	const struct CMUnitTest mcfd_cipher_decrypt_tests[] = {
		cmocka_unit_test_setup_teardown(mcfd_cipher_decrypt_normal,
				mcfd_cipher_setup, mcfd_cipher_teardown)
	};

	fprintf(stderr, "mcfd_cipher_decrypt:\n");
	res |= cmocka_run_group_tests(mcfd_cipher_decrypt_tests, NULL, NULL);
	fprintf(stderr, "\n");

	return res;
}
