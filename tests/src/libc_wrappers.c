#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libc_wrappers.h"

int __activate_wrap_alloc = 0;

void *__wrap_alloc(size_t nmemb, size_t size)
{
	if (__activate_wrap_alloc == 0) {
		return __real_calloc(nmemb, size);
	}

	check_expected(nmemb);
	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		ret = __real_calloc(nmemb, size);
	}

	return ret;
}

int __activate_wrap_malloc = 0;

void *__wrap_malloc(size_t size)
{
	if (__activate_wrap_malloc == 0) {
		return __wrap_alloc(size, 1);
	}

	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		ret = __real_malloc(size);
	}

	return ret;
}

int __activate_wrap_calloc = 0;

void *__wrap_calloc(size_t nmemb, size_t size)
{
	if (__activate_wrap_calloc == 0) {
		return __wrap_alloc(nmemb, size);
	}

	check_expected(nmemb);
	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		ret = __real_calloc(nmemb, size);
	}

	return ret;
}
