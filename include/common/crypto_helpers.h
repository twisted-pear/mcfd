#ifndef __CRYPTO_HELPERS_H__
#define __CRYPTO_HELPERS_H__

#include <stdint.h>

void explicit_bzero(void *s, const size_t n)
	__attribute__((noinline, noclone));

int timingsafe_bcmp(const void *s1, const void *s2, const size_t n)
	__attribute__((optimize("O0"), noinline));

#endif /* __CRYPTO_HELPERS_H__ */
