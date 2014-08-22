#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <assert.h>

#include "libc_wrappers.h"

static int __test_malloc_active = 0;
static void *__test_malloc(size_t size)
{
	__test_malloc_active = 1;
	void *ret = test_malloc(size);
	__test_malloc_active = 0;
	return ret;
}

static int __test_calloc_active = 0;
static void *__test_calloc(size_t nmemb, size_t size)
{
	__test_calloc_active = 1;
	void *ret = test_calloc(nmemb, size);
	__test_calloc_active = 0;
	return ret;
}

static int __test_free_active = 0;
static void __test_free(void *ptr)
{
	__test_free_active = 1;
	test_free(ptr);
	__test_free_active = 0;
}

int __activate_wrap_alloc = 0;

void *__wrap_alloc(size_t nmemb, size_t size, alloc_t alloc)
{
	if (__activate_wrap_alloc == 0) {
		switch (alloc) {
		case ALLOC_MALLOC: return __test_malloc(nmemb);
		case ALLOC_CALLOC: return __test_calloc(nmemb, size);
		default: assert(0);
		}
	}

	check_expected(nmemb);
	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		switch (alloc) {
		case ALLOC_MALLOC: return __test_malloc(nmemb);
		case ALLOC_CALLOC: return __test_calloc(nmemb, size);
		default: assert(0);
		}
	}

	return ret;
}

void __wrap_free(void *ptr)
{
	if (__test_free_active != 0) {
		__real_free(ptr);
		return;
	}

	__test_free(ptr);
}

int __activate_wrap_malloc = 0;

void *__wrap_malloc(size_t size)
{
	if (__test_malloc_active != 0) {
		return __real_malloc(size);
	}

	if (__activate_wrap_malloc == 0) {
		return __wrap_alloc(size, 1, ALLOC_MALLOC);
	}

	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		ret = __test_malloc(size);
	}

	return ret;
}

int __activate_wrap_calloc = 0;

void *__wrap_calloc(size_t nmemb, size_t size)
{
	if (__test_calloc_active != 0) {
		return __real_calloc(nmemb, size);
	}

	if (__activate_wrap_calloc == 0) {
		return __wrap_alloc(nmemb, size, ALLOC_CALLOC);
	}

	check_expected(nmemb);
	check_expected(size);

	void *ret = mock_ptr_type(void *);
	if (ret == __WRAP_ALLOC_NEW) {
		ret = __test_calloc(nmemb, size);
	}

	return ret;
}
