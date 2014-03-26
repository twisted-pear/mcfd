#include <stdlib.h>

#include <assert.h>

#include "common.h"

int const_cmp(const unsigned char *s1, const unsigned char *s2, size_t n)
{
	unsigned char accum = 0;

	size_t i;
	for (i = 0; i < n; i++) {
		accum |= s1[i] ^ s2[i];
	}

	/* Normalize return value. */
	int ret = 0;
	for (i = 0; i < sizeof(accum) * 8; i++) {
		ret |= accum & 0x1;
		accum >>= 1;
	}

	assert(accum == 0);
	assert(ret == 1 || ret == 0);

	return ret;
}

void xor_and_permute_block(unsigned char *state, const size_t rate, permutation *p,
		const unsigned char *input)
{
	assert(state != NULL && p != NULL && rate > 0 && input != NULL);

	size_t i;
	for (i = 0; i < rate / 8; i++) {
		state[i] ^= input[i];
	}

	/* Handle the last byte and make sure we only use the relevant bits. */
	size_t remaining_bits = rate % 8;
	if (remaining_bits != 0) {
		unsigned char last_byte = input[i];
		last_byte &= (1 << remaining_bits) - 1;
		state[i] ^= last_byte;
	}

	p->f(p, state);
}
