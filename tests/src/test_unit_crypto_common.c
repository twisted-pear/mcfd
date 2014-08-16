#include <stdlib.h>

#include <crypto_helpers.h>

#include <check.h>

Suite *create_test_suite(void)
{
	Suite *s = suite_create("Crypto Helpers");

	return s;
}
