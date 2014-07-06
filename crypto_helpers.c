#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"

void explicit_bzero(void *s, const size_t n)
{
	memset(s, 0, n);
}

int timingsafe_bcmp(const void *s1, const void *s2, const size_t n)
{
	const unsigned char *a = s1;
	const unsigned char *b = s2;
	unsigned char ret = 0;

	size_t i;
	for (i = 0; i < n; i++) {
		ret |= a[i] ^ b[i];
	}

	return (ret != 0);
}

void xor_and_permute_block(unsigned char *state, const size_t rate, permutation *p,
		const unsigned char *input)
{
	assert((state != NULL) & (p != NULL) & (rate > 0) & (input != NULL));

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
