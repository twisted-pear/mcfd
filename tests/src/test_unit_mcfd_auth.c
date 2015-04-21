#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <mcfd_auth.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

#define CREATE_MAX_ALLOC_SIZE 256
#define CREATE_MAX_ALLOCS 10

void curve25519_clamp(unsigned char *privkey __attribute__((unused)))
{
}

void curve25519_public(const unsigned char *privkey __attribute__((unused)),
		unsigned char *pubkey __attribute__((unused)))
{
}

void curve25519(unsigned char *shared __attribute__((unused)),
		const unsigned char *my_privkey __attribute__((unused)),
		const unsigned char *their_pubkey __attribute__((unused)))
{
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

static void mcfd_auth_init_setup(void **state __attribute__((unused)))
{
}

static void mcfd_auth_init_teardown(void **state __attribute__((unused)))
{
}

static void mcfd_auth_init_normal(void **state __attribute__((unused)))
{
}

int run_unit_tests(void)
{
	int res = 0;

	const UnitTest mcfd_auth_init_tests[] = {
		unit_test_setup_teardown(mcfd_auth_init_normal,
				mcfd_auth_init_setup, mcfd_auth_init_teardown)
	};

	fprintf(stderr, "mcfd_auth_init:\n");
	res |= run_tests(mcfd_auth_init_tests);
	fprintf(stderr, "\n");

	return res;
}
