#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <curve25519.h>
#include <mcfd_auth.h>
#include <mcfd_cipher.h>

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
#define IN_PATTERN 0x33
#define ENC_PATTERN 0x44
#define PUBKEY_PATTERN 0x55
#define FAIL_PATTERN 0x66

#define EMPTY_PATTERN 0xFF

#define VAL_ENC 0x70
#define VAL_DEC 0x07

struct mcfd_cipher_t {
	int val;
};

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

	size_t i;
	for (i = 0; i < CURVE25519_PRIVATE_BYTES; i++) {
		assert_int_equal(privkey[i], PRIVKEY_PATTERN);
	}

	memset(pubkey, PUBKEY_PATTERN, CURVE25519_PUBLIC_BYTES);
}

void curve25519(unsigned char *shared, const unsigned char *my_privkey,
		const unsigned char *their_pubkey)
{
	check_expected(shared);
	check_expected(my_privkey);
	check_expected(their_pubkey);
}

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag)
{
	check_expected(cipher);
	check_expected(plaintext);
	check_expected(plaintext_bytes);
	check_expected(ciphertext);
	check_expected(tag);

	assert_int_equal(cipher->val, VAL_ENC);
	cipher->val = VAL_DEC;

	int ret = mock_type(int);

	if (ret == 0) {
		memset(ciphertext, ENC_PATTERN, plaintext_bytes);
		memset(tag, ENC_PATTERN, MCFD_TAG_BYTES);
	}

	return ret;
}

int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext)
{
	check_expected(cipher);
	check_expected(ciphertext);
	check_expected(ciphertext_bytes);
	check_expected(tag);
	check_expected(plaintext);

	assert_int_equal(cipher->val, VAL_DEC);
	cipher->val = VAL_ENC;

	int ret = mock_type(int);

	if (ret == 0) {
		memset(plaintext, RANDOM_PATTERN, ciphertext_bytes);
	} else if (ret == FAIL_PATTERN) {
		memset(plaintext, FAIL_PATTERN, ciphertext_bytes);
		ret = 0;
	}

	return ret;
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

static void mcfd_auth_phase1_srv_setup(void **state __attribute__((unused)))
{
	mcfd_auth_init_setup(state);

	out_bytes = malloc(MCFD_AUTH_PHASE1_SERVER_OUT_BYTES);
	assert_non_null(out_bytes);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_SERVER_OUT_BYTES);

	mcfd_auth_init_success();

	ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);
}

static void mcfd_auth_phase1_srv_teardown(void **state __attribute__((unused)))
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

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], RANDOM_PATTERN);
	}
}

mcfd_cipher *c_auth;
unsigned char *in_bytes;

static void mcfd_auth_phase1_clt_setup(void **state __attribute__((unused)))
{
	mcfd_auth_init_setup(state);

	c_auth = malloc(sizeof(struct mcfd_cipher_t));
	assert_non_null(c_auth);
	c_auth->val = VAL_ENC;

	in_bytes = malloc(MCFD_AUTH_PHASE1_CLIENT_IN_BYTES);
	assert_non_null(in_bytes);
	memset(in_bytes, IN_PATTERN, MCFD_AUTH_PHASE1_CLIENT_IN_BYTES);

	out_bytes = malloc(MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES);
	assert_non_null(out_bytes);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES);

	mcfd_auth_init_success();

	ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);
}

static void mcfd_auth_phase1_clt_teardown(void **state __attribute__((unused)))
{
	mcfd_auth_free(ctx);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_IN_BYTES; i++) {
		assert_int_equal(in_bytes[i], IN_PATTERN);
	}

	free(c_auth);
	free(in_bytes);
	free(out_bytes);

	mcfd_auth_init_teardown(state);
}

static void mcfd_auth_phase1_client_success(void)
{
	expect_any_count(curve25519_public, privkey, 2);
	expect_any_count(curve25519_public, pubkey, 2);

	expect_value(mcfd_cipher_encrypt, cipher, c_auth);
	expect_any(mcfd_cipher_encrypt, plaintext);
	expect_value(mcfd_cipher_encrypt, plaintext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_encrypt, ciphertext, out_bytes);
	expect_value(mcfd_cipher_encrypt, tag, out_bytes + AUTH_MSG_SIZE);
	will_return(mcfd_cipher_encrypt, 0);
}

static void mcfd_auth_phase1_client_ctx_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_client(NULL, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_cauth_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_client(ctx, NULL, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_in_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, NULL, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_out_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, in_bytes, NULL), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_noalloc(void **state __attribute__((unused)))
{
	/* mcfd_auth_phase1_client has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	int ret = mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes);

	__activate_wrap_alloc = 0;

	assert_int_equal(ret, 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_alloc_limited(void **state __attribute__((unused)))
{
	mcfd_auth_phase1_client_success();

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	int ret = 1;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		ret = mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes);
		if (ret == 0) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_int_equal(ret, 0);

	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], ENC_PATTERN);
	}
}

static void mcfd_auth_phase1_client_encrypt_fail(void **state __attribute__((unused)))
{
	expect_any_count(curve25519_public, privkey, 2);
	expect_any_count(curve25519_public, pubkey, 2);

	expect_value(mcfd_cipher_encrypt, cipher, c_auth);
	expect_any(mcfd_cipher_encrypt, plaintext);
	expect_value(mcfd_cipher_encrypt, plaintext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_encrypt, ciphertext, out_bytes);
	expect_value(mcfd_cipher_encrypt, tag, out_bytes + AUTH_MSG_SIZE);
	will_return(mcfd_cipher_encrypt, 1);

	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes), 1);

	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_normal(void **state __attribute__((unused)));

static void mcfd_auth_phase1_client_wrong_phase(void **state __attribute__((unused)))
{
	mcfd_auth_phase1_client_normal(state);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES);

	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase1_client_normal(void **state __attribute__((unused)))
{
	mcfd_auth_phase1_client_success();

	assert_int_equal(mcfd_auth_phase1_client(ctx, c_auth, in_bytes, out_bytes), 0);

	/* TODO: test if phase 2 accepts ctx */

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], ENC_PATTERN);
	}
}

static void mcfd_auth_phase2_srv_setup(void **state __attribute__((unused)))
{
	mcfd_auth_init_setup(state);

	c_auth = malloc(sizeof(struct mcfd_cipher_t));
	assert_non_null(c_auth);
	c_auth->val = VAL_DEC;

	in_bytes = malloc(MCFD_AUTH_PHASE2_SERVER_IN_BYTES);
	assert_non_null(in_bytes);
	memset(in_bytes, IN_PATTERN, MCFD_AUTH_PHASE2_SERVER_IN_BYTES);

	out_bytes = malloc(MCFD_AUTH_PHASE2_SERVER_OUT_BYTES);
	assert_non_null(out_bytes);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE2_SERVER_OUT_BYTES);

	mcfd_auth_init_success();

	ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);

	mcfd_auth_phase1_server_normal(state);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE2_SERVER_OUT_BYTES);
}

static void mcfd_auth_phase2_srv_teardown(void **state __attribute__((unused)))
{
	mcfd_auth_free(ctx);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_IN_BYTES; i++) {
		assert_int_equal(in_bytes[i], IN_PATTERN);
	}

	free(c_auth);
	free(in_bytes);
	free(out_bytes);

	mcfd_auth_init_teardown(state);
}

static void mcfd_auth_phase2_server_success(void)
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, 0);

	expect_any_count(curve25519_public, privkey, 2);
	expect_any_count(curve25519_public, pubkey, 2);

	expect_value(mcfd_cipher_encrypt, cipher, c_auth);
	expect_any(mcfd_cipher_encrypt, plaintext);
	expect_value(mcfd_cipher_encrypt, plaintext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_encrypt, ciphertext, out_bytes);
	expect_value(mcfd_cipher_encrypt, tag, out_bytes + AUTH_MSG_SIZE);
	will_return(mcfd_cipher_encrypt, 0);
}

static void mcfd_auth_phase2_server_ctx_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_server(NULL, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_cauth_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_server(ctx, NULL, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_in_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, NULL, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_out_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, NULL), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_noalloc(void **state __attribute__((unused)))
{
	/* mcfd_auth_phase2_server has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	int ret = mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes);

	__activate_wrap_alloc = 0;

	assert_int_equal(ret, 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_alloc_limited(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_server_success();

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	int ret = 1;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		ret = mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes);
		if (ret == 0) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_int_equal(ret, 0);

	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], ENC_PATTERN);
	}
}

static void mcfd_auth_phase2_server_challenge_fail(void **state __attribute__((unused)))
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, FAIL_PATTERN);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_decrypt_fail(void **state __attribute__((unused)))
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, 1);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_encrypt_fail(void **state __attribute__((unused)))
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, 0);

	expect_any_count(curve25519_public, privkey, 2);
	expect_any_count(curve25519_public, pubkey, 2);

	expect_value(mcfd_cipher_encrypt, cipher, c_auth);
	expect_any(mcfd_cipher_encrypt, plaintext);
	expect_value(mcfd_cipher_encrypt, plaintext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_encrypt, ciphertext, out_bytes);
	expect_value(mcfd_cipher_encrypt, tag, out_bytes + AUTH_MSG_SIZE);
	will_return(mcfd_cipher_encrypt, 1);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_normal(void **state __attribute__((unused)));

static void mcfd_auth_phase2_server_wrong_phase(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_server_normal(state);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE2_SERVER_OUT_BYTES);

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 1);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], EMPTY_PATTERN);
	}
}

static void mcfd_auth_phase2_server_normal(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_server_success();

	assert_int_equal(mcfd_auth_phase2_server(ctx, c_auth, in_bytes, out_bytes), 0);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_SERVER_OUT_BYTES; i++) {
		assert_int_equal(out_bytes[i], ENC_PATTERN);
	}
}

static void mcfd_auth_phase2_clt_setup(void **state __attribute__((unused)))
{
	mcfd_auth_init_setup(state);

	c_auth = malloc(sizeof(struct mcfd_cipher_t));
	assert_non_null(c_auth);
	c_auth->val = VAL_ENC;

	in_bytes = malloc(MCFD_AUTH_PHASE2_CLIENT_IN_BYTES);
	assert_non_null(in_bytes);
	memset(in_bytes, RANDOM_PATTERN, MCFD_AUTH_PHASE2_CLIENT_IN_BYTES);

	mcfd_auth_init_success();

	ctx = mcfd_auth_init(random_bytes);
	assert_non_null(ctx);

	out_bytes = malloc(MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES);
	assert_non_null(out_bytes);
	memset(out_bytes, EMPTY_PATTERN, MCFD_AUTH_PHASE1_CLIENT_OUT_BYTES);

	mcfd_auth_phase1_client_normal(state);

	free(out_bytes);

	memset(in_bytes, IN_PATTERN, MCFD_AUTH_PHASE2_CLIENT_IN_BYTES);
}

static void mcfd_auth_phase2_clt_teardown(void **state __attribute__((unused)))
{
	mcfd_auth_free(ctx);

	size_t i;
	for (i = 0; i < MCFD_AUTH_PHASE2_CLIENT_IN_BYTES; i++) {
		assert_int_equal(in_bytes[i], IN_PATTERN);
	}

	free(c_auth);
	free(in_bytes);

	mcfd_auth_init_teardown(state);
}

static void mcfd_auth_phase2_client_success(void)
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, 0);
}

static void mcfd_auth_phase2_client_ctx_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_client(NULL, c_auth, in_bytes), 1);
}

static void mcfd_auth_phase2_client_cauth_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_client(ctx, NULL, in_bytes), 1);
}

static void mcfd_auth_phase2_client_in_null(void **state __attribute__((unused)))
{
	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, NULL), 1);
}

static void mcfd_auth_phase2_client_noalloc(void **state __attribute__((unused)))
{
	/* mcfd_auth_phase2_client has to allocate at least some memory */

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);
	will_return_count(__wrap_alloc, NULL, -1);

	__activate_wrap_alloc = 1;

	int ret = mcfd_auth_phase2_client(ctx, c_auth, in_bytes);

	__activate_wrap_alloc = 0;

	assert_int_equal(ret, 1);
}

static void mcfd_auth_phase2_client_alloc_limited(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_client_success();

	expect_any_count(__wrap_alloc, nmemb, -1);
	expect_any_count(__wrap_alloc, size, -1);

	int ret = 1;

	size_t i;
	for (i = 1; i <= CREATE_MAX_ALLOCS; i++) {
		will_return_count(__wrap_alloc, __WRAP_ALLOC_NEW, i);
		will_return_count(__wrap_alloc, NULL, 1);

		__activate_wrap_alloc = 1;

		ret = mcfd_auth_phase2_client(ctx, c_auth, in_bytes);
		if (ret == 0) {
			break;
		}

		__activate_wrap_alloc = 0;
	}

	assert_null(__wrap_alloc(0, 1, ALLOC_MALLOC));
	__activate_wrap_alloc = 0;
	assert_in_range(i, 1, CREATE_MAX_ALLOCS);

	assert_int_equal(ret, 0);
}

static void mcfd_auth_phase2_client_challenge_fail(void **state __attribute__((unused)))
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, FAIL_PATTERN);

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 1);

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 1);
}

static void mcfd_auth_phase2_client_decrypt_fail(void **state __attribute__((unused)))
{
	expect_value(mcfd_cipher_decrypt, cipher, c_auth);
	expect_value(mcfd_cipher_decrypt, ciphertext, in_bytes);
	expect_value(mcfd_cipher_decrypt, ciphertext_bytes, AUTH_MSG_SIZE);
	expect_value(mcfd_cipher_decrypt, tag, in_bytes + AUTH_MSG_SIZE);
	expect_any(mcfd_cipher_decrypt, plaintext);
	will_return(mcfd_cipher_decrypt, 1);

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 1);

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 1);
}

static void mcfd_auth_phase2_client_normal(void **state __attribute__((unused)));

static void mcfd_auth_phase2_client_wrong_phase(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_client_normal(state);

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 1);
}

static void mcfd_auth_phase2_client_normal(void **state __attribute__((unused)))
{
	mcfd_auth_phase2_client_success();

	assert_int_equal(mcfd_auth_phase2_client(ctx, c_auth, in_bytes), 0);
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
				mcfd_auth_phase1_srv_setup, mcfd_auth_phase1_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_out_null,
				mcfd_auth_phase1_srv_setup, mcfd_auth_phase1_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_wrong_phase,
				mcfd_auth_phase1_srv_setup, mcfd_auth_phase1_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_server_normal,
				mcfd_auth_phase1_srv_setup, mcfd_auth_phase1_srv_teardown)
	};

	fprintf(stderr, "mcfd_auth_phase1_server:\n");
	res |= run_tests(mcfd_auth_phase1_server_tests);
	fprintf(stderr, "\n");

	const UnitTest mcfd_auth_phase1_client_tests[] = {
		unit_test_setup_teardown(mcfd_auth_phase1_client_ctx_null,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_cauth_null,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_in_null,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_out_null,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_noalloc,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_alloc_limited,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_encrypt_fail,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_wrong_phase,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase1_client_normal,
				mcfd_auth_phase1_clt_setup, mcfd_auth_phase1_clt_teardown)
	};

	fprintf(stderr, "mcfd_auth_phase1_client:\n");
	res |= run_tests(mcfd_auth_phase1_client_tests);
	fprintf(stderr, "\n");

	const UnitTest mcfd_auth_phase2_server_tests[] = {
		unit_test_setup_teardown(mcfd_auth_phase2_server_ctx_null,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_cauth_null,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_in_null,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_out_null,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_noalloc,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_alloc_limited,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_challenge_fail,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_decrypt_fail,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_encrypt_fail,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_wrong_phase,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_server_normal,
				mcfd_auth_phase2_srv_setup, mcfd_auth_phase2_srv_teardown)
	};

	fprintf(stderr, "mcfd_auth_phase2_server:\n");
	res |= run_tests(mcfd_auth_phase2_server_tests);
	fprintf(stderr, "\n");

	const UnitTest mcfd_auth_phase2_client_tests[] = {
		unit_test_setup_teardown(mcfd_auth_phase2_client_ctx_null,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_cauth_null,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_in_null,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_noalloc,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_alloc_limited,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_challenge_fail,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_decrypt_fail,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_wrong_phase,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown),
		unit_test_setup_teardown(mcfd_auth_phase2_client_normal,
				mcfd_auth_phase2_clt_setup, mcfd_auth_phase2_clt_teardown)
	};

	fprintf(stderr, "mcfd_auth_phase2_client:\n");
	res |= run_tests(mcfd_auth_phase2_client_tests);
	fprintf(stderr, "\n");

	return res;
}
