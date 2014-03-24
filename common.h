#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

#include "permutation.h"

void xor_and_permute_block(unsigned char *state, const size_t rate, permutation *p,
		const unsigned char *input);

#endif /* __COMMON_H__ */