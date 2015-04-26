#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <curve25519.h>
#include <mcfd_auth.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_MAX_ALLOC_SIZE 256
#define CREATE_MAX_ALLOCS 10

#define RANDOM_PATTERN 0x11
#define PRIVKEY_PATTERN 0x22

#define EMPTY_PATTERN 0xFF

void curve25519_clamp(unsigned char *privkey)
{
	check_expected(privkey);

	size_t i;
	for (i = 0; i < CURVE25519_PRIVATE_BYTES; i++) {
		assert_int_equal(privkey[i], RANDOM_PATTERN);
	}

	memset(privkey, PRIVKEY_PATTERN, CURVE25519_PRIVATE_BYTES);
}

void curve25519_public(const unsigned char *privkey, unsigned char *pubkey)
{
	check_expected(privkey);
	check_expected(pubkey);
}

void curve25519(unsigned char *shared, const unsigned char *my_privkey,
		const unsigned char *their_pubkey)
{
	check_expected(shared);
	check_expected(my_privkey);
	check_expected(their_pubkey);
}

int mcfd_cipher_encrypt(mcfd_cipher *cipher __attribute__((unused)),
		const unsigned char *plaintext __attribute__((unused)),
		const size_t plaintext_bytes __attribute__((unused)),
		unsigned char *ciphertext __attribute__((unused)),
		unsigned char *tag __attribute__((unused)))
{
	return 0;
}

int mcfd_cipher_decrypt(mcfd_cipher *cipher __attribute__((unused)),
		const unsigned char *ciphertext __attribute__((unused)),
		const size_t ciphertext_bytes __attribute__((unused)),
		const unsigned char *tag __attribute__((unused)),
		unsigned char *plaintext __attribute__((unused)))
{
	return 0;
}

int mcfd_kdf(const char *pass __attribute__((unused)),
		const size_t pass_len __attribute__((unused)),
		const unsigned char *salt __attribute__((unused)),
		const size_t iterations __attribute__((unused)),
		unsigned char *key __attribute__((unused)),
		const size_t key_bits __attribute__((unused)))
{
	return 0;
}

static unsigned char random_bytes[MCFD_AUTH_RANDOM_BYTES];

static void mcfd_auth_init_setup(void **state __attribute__((unused)))
{
	memset(random_bytes, RANDOM_PATTERN, MCFD_AUTH_RANDOM_BYTES);
}

static void mcfd_auth_init_teardown(void **state __attribute__((unused)))
{
	size_t i;
	for (i = 0; i < MCFD_AUTH_RANDOM_BYTES; i++) {
		assert_int_equal(random_bytes[i], RANDOM_PATTERN);
	}
}

static void mcfd_auth_init_success(void)
{
	expect_any_count(curve25519_clamp, privkey, 2);
}

static void mcfd_auth_init_in_null(void **state __attribute__((unused)))
{
	assert_null(mcfd_auth_init(NULL));
}

static void mcfd_auth_init_noalloc(void **state __attribute__((unused)))
{
	/* mcfd_auth_init has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	mcfd_auth_context *ctx = mcfd_auth_init(random_bytes);

	__activate_wrap_alloc = 0;

	assert_null(ctx);
}

static void mcfd_auth_init_alloc_limited(void **state __attribute__((unused)))
{
	mcfd_auth_init_success();

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	mcfd_auth_context *ctx = NULL;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		ctx = mcfd_auth_init(random_bytes);
		if (ctx != NULL) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_non_null(ctx);

	mcfd_auth_free(ctx);
}

static void mcfd_auth_init_normal(void **state __attribute__((unused)))
{
	mcfd_auth_init_success();

	mcfd_auth_context *ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);

	mcfd_auth_free(ctx);
}

mcfd_auth_context *ctx;
unsigned char *out_bytes;

static void mcfd_auth_phase1_setup(void **state __attribute__((unused)))
{
	mcfd_auth_init_setup(state);

	out_bytes = malloc(MCFD_AUTH_PHASE1_SERVER_OUT_BYTES);
	assert_non_null(out_bytes);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_SERVER_OUT_BYTES);

	mcfd_auth_init_success();

	ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);
}

static void mcfd_auth_phase1_teardown(void **state __attribute__((unused)))
{
	mcfd_auth_free(ctx);

	free(out_bytes);

	mcfd_auth_init_teardown(state);
}

static void mcfd_auth_phase1_server_ctx_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_server(NULL, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_server_out_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_server(ctx, NULL), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_server_normal(void **state __attribute__((unused)));

static void mcfd_auth_phase1_server_wrong_phase(void **state __attribute__((unused)))
{
	mcfd_auth_phase1_server_normal(state);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_SERVER_OUT_BYTES);

	assert_int_equal(mcfd_auth_phase1_server(ctx, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_server_normal(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_server(ctx, out_bytes), 0);

	/* TODO: test if phase 2 accepts ctx */

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], RANDOM_PATTERN);
	}
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest mcfd_auth_init_tests[] = {
		unit_test_setup_teardown(mcfd_auth_init_in_null,
				mcfd_auth_init_setup, mcfd_auth_init_teardown),
		unit_test_setup_teardown(mcfd_auth_init_noalloc,
				mcfd_auth_init_setup, mcfd_auth_init_teardown),
		unit_test_setup_teardown(mcfd_auth_init_alloc_limited,
				mcfd_auth_init_setup, mcfd_auth_init_teardown),
		unit_test_setup_teardown(mcfd_auth_init_normal,
				mcfd_auth_init_setup, mcfd_auth_init_teardown)
	};

	fprintf(stderr, "mcfd_auth_init:\n");
	res |= run_tests(mcfd_auth_init_tests);
	fprintf(stderr, "\n");

	const UnitTest mcfd_auth_phase1_server_tests[] = {
		unit_test_setup_teardown(mcfd_auth_phase1_server_ctx_null,
				mcfd_auth_phase1_setup, mcfd_auth_phase1_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_out_null,
				mcfd_auth_phase1_setup, mcfd_auth_phase1_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_wrong_phase,
				mcfd_auth_phase1_setup, mcfd_auth_phase1_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_normal,
				mcfd_auth_phase1_setup, mcfd_auth_phase1_teardown)
	};

	fprintf(stderr, "mcfd_auth_phase1_server:\n");
	res |= run_tests(mcfd_auth_phase1_server_tests);
	fprintf(stderr, "\n");

	return res;
}
