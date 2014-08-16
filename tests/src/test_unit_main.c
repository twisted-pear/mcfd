#include <stdlib.h>

#include <check.h>

extern Suite *create_test_suite(void);

int main(void)
{
	Suite *s = create_test_suite();

	SRunner *sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	int nfailed = srunner_ntests_failed(sr);

	srunner_free(sr);

	if (nfailed != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
