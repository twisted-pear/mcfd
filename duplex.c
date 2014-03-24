#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "duplex.h"
#include "common.h"

struct internals {
	unsigned char *state;
	unsigned char *remaining;
};

duplex *duplex_init(permutation *f, pad *p, const size_t rate)
{
	assert(f != NULL && p != NULL);

	if (f->width == 0) {
		return NULL;
	}

	if (f->width % 8 != 0) {
		return NULL;
	}

	if (rate > f->width) {
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

	dp->internal = malloc(sizeof(struct internals));
	if (dp->internal == NULL) {
		free(dp);
		return NULL;
	}

	struct internals *internal = (struct internals *) dp->internal;

	internal->state = calloc(f->width / 8, 1);
	if (internal->state == NULL) {
		free(internal);
		free(dp);
		return NULL;
	}

	internal->remaining = calloc((rate + 7) / 8, 1);
	if (internal->remaining == NULL) {
		free(internal->state);
		free(internal);
		free(dp);
		return NULL;
	}

	return dp;
}

void duplex_free(duplex *dp)
{
	assert(dp != NULL);
	assert(dp->internal != NULL);

	struct internals *internal = (struct internals *) dp->internal;
	free(internal->state);
	free(internal->remaining);
	free(internal);

	free(dp);
}

int duplex_duplexing(duplex *dp, const unsigned char *input, const size_t input_bit_len,
		unsigned char *output, const size_t output_bit_len)
{
	assert(dp != NULL);
	assert(input != NULL || input_bit_len == 0);
	assert(output != NULL || output_bit_len == 0);

	struct internals *internal = (struct internals *) dp->internal;

	if (input_bit_len > dp->max_duplex_rate) {
		return 1;
	}

	if (output_bit_len > dp->rate) {
		return 1;
	}

	/* FIXME: probably useless */
	memset(internal->remaining, 0, (dp->rate + 7) / 8);

	memcpy(internal->remaining, input, (input_bit_len + 7) / 8);

	/* Apply padding and add last block. */
	if (dp->p->pf(dp->p, internal->remaining, input_bit_len) == 0) {
		return 1;
	}
	xor_and_permute_block(internal->state, dp->rate, dp->f, internal->remaining);
	if (dp->p->pf(dp->p, internal->remaining, input_bit_len) != 0) {
		return 1;
	}

	memcpy(output, internal->state, output_bit_len / 8);

	/* Handle the last byte and make sure we only use the relevant bits. */
	size_t remaining_bits = output_bit_len % 8;
	size_t last_idx = output_bit_len / 8;
	if (remaining_bits != 0) {
		unsigned char last_byte = internal->state[last_idx];
		last_byte <<= 8 - remaining_bits;
		output[last_idx] = last_byte;
	}

	return 0;
}
