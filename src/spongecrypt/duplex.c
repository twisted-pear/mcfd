#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "duplex.h"
#include "crypto_helpers.h"

void duplex_clear_buffers(duplex *dp)
{
	assert(dp != NULL);
}

duplex *duplex_init(permutation *f, pad *p, const size_t rate)
{
	if (f == NULL || p == NULL) {
		return NULL;
	}

	if (f->width == 0) {
		return NULL;
	}

	if (f->width % 8 != 0) {
		return NULL;
	}

	if (rate >= f->width) {
		return NULL;
	}

	if (rate <= p->min_bit_len) {
		return NULL;
	}

	if (p->rate != rate) {
		return NULL;
	}

	duplex *dp = malloc(sizeof(duplex));
	if (dp == NULL) {
		return NULL;
	}

	dp->f = f;
	dp->p = p;
	dp->rate = rate;
	dp->max_duplex_rate = rate - p->min_bit_len;

	dp->internal = NULL;

	return dp;
}

void duplex_free(duplex *dp)
{
	assert(dp != NULL);

	duplex_clear_buffers(dp);

	free(dp);
}

int duplex_duplexing(duplex *dp, const unsigned char *input, const size_t input_bit_len,
		unsigned char *output, const size_t output_bit_len)
{
	assert(dp != NULL);
	assert((input != NULL) | (input_bit_len == 0));
	assert((output != NULL) | (output_bit_len == 0));

	if (input_bit_len > dp->max_duplex_rate) {
		return 1;
	}

	if (output_bit_len > dp->rate) {
		return 1;
	}

	/* Apply padding and add last block. */
	if (dp->f->xor(dp->f, 0, input, input_bit_len) != 0) {
		assert(0);
	}
	if (dp->p->pf(dp->p, dp->f, input_bit_len) != 0) {
		assert(0);
	}

	if (dp->f->get(dp->f, 0, output, output_bit_len) != 0) {
		assert(0);
	}

	return 0;
}
