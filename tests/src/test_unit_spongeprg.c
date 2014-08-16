#include <stdlib.h>

#include <pad.h>
#include <permutation.h>
#include <spongeprg.h>

#include <check.h>

Suite *create_test_suite(void)
{
	Suite *s = suite_create("SpongePRG");

	return s;
}
