#ifndef __LIBC_WRAPPERS_H__
#define __LIBC_WRAPPERS_H__

#include <stdint.h>

#define __WRAP_ALLOC_NEW ((void *) -1)

typedef enum {
	ALLOC_MALLOC,
	ALLOC_CALLOC
} alloc_t;

extern int __activate_wrap_alloc;
void *__wrap_alloc(size_t nmemb, size_t size, alloc_t alloc);

extern void __real_free(void *ptr);
void __wrap_free(void *ptr);

extern void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
extern int __activate_wrap_malloc;

extern void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
extern int __activate_wrap_calloc;

#endif /* __LIBC_WRAPPERS_H__ */
