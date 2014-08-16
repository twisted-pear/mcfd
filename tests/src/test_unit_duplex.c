#include <stdlib.h>

#include <pad.h>
#include <permutation.h>
#include <duplex.h>

#include <check.h>

Suite *create_test_suite(void)
{
	Suite *s = suite_create("Duplex");

	return s;
}
