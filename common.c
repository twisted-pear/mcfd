#include <stdlib.h>

#include <assert.h>

#include "common.h"

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
		last_byte &= ~((1 << (8 - remaining_bits)) - 1);
		state[i] ^= last_byte;
	}

	p->f(p, state);
}
