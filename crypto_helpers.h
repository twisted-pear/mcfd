#ifndef __CRYPTO_HELPERS_H__
#define __CRYPTO_HELPERS_H__

#include <stdint.h>

#include "permutation.h"

int const_cmp(const unsigned char *s1, const unsigned char *s2, size_t n);

void xor_and_permute_block(unsigned char *state, const size_t rate, permutation *p,
		const unsigned char *input);

#endif /* __CRYPTO_HELPERS_H__ */