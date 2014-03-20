#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "sponge.h"
#include "common.h"

struct internals {
	unsigned char *state;
	unsigned char *remaining;
	size_t remaining_bits;
};

sponge *sponge_init(permutation *f, pad *p, const size_t rate)
{
	assert(f != NULL && p != NULL);

	if (rate == 0 || f->width == 0) {
		return NULL;
	}

	if (rate > f->width) {
		return NULL;
	}

	if (rate % 8 != 0 || f->width % 8 != 0) {
		return NULL;
	}

	if (p->rate != rate) {
		return NULL;
	}

	sponge *sp = malloc(sizeof(sponge));
	if (sp == NULL) {
		return NULL;
	}

	sp->f = f;
	sp->p = p;
	sp->rate = rate;
	sp->internal = malloc(sizeof(struct internals));
	if (sp->internal == NULL) {
		free(sp);
		return NULL;
	}

	struct internals *internal = (struct internals *) sp->internal;

	internal->state = calloc(f->width / 8, 1);
	if (internal->state == NULL) {
		free(internal);
		free(sp);
		return NULL;
	}

	internal->remaining = calloc(rate / 8, 1);
	if (internal->remaining == NULL) {
		free(internal->state);
		free(internal);
		free(sp);
		return NULL;
	}

	internal->remaining_bits = 0;

	return sp;
}

void sponge_free(sponge *sp)
{
	assert(sp != NULL);

	struct internals *internal = (struct internals *) sp->internal;
	free(internal->state);
	free(internal->remaining);
	free(internal);

	free(sp);
}

int sponge_absorb(sponge *sp, const unsigned char *input, const size_t input_bit_len)
{
	assert(sp != NULL && input != NULL);

	struct internals *internal = (struct internals *) sp->internal;

	assert(internal->remaining_bits < sp->rate);

	/* Don't allow absorbs with partial bytes, except at the end.
	 * Rationale: The reference implementation doesn't allow this either (and it's easier). */
	if (internal->remaining_bits % 8 != 0) {
		return 1;
	}

	/* Finish absorbing any started block from a previous sponge_absorb. */
	size_t bits_needed = 0;
	if (internal->remaining_bits != 0) {
		bits_needed = sp->rate - internal->remaining_bits;
		memcpy(internal->remaining + internal->remaining_bits / 8, input, bits_needed / 8);

		xor_and_permute_block(internal->state, sp->rate, sp->f, internal->remaining);
	}

	/* Absorb full blocks in the input. */
	size_t remaining_bit_len = input_bit_len - bits_needed;
	const unsigned char *begin_full = input + bits_needed / 8;

	while (remaining_bit_len >= sp->rate) {
		xor_and_permute_block(internal->state, sp->rate, sp->f, begin_full);

		remaining_bit_len -= sp->rate;
		begin_full += sp->rate / 8;
	}

	/* Copy remainder into sp->internal for further use. */
	internal->remaining_bits = remaining_bit_len;
	memcpy(internal->remaining, begin_full, (remaining_bit_len + 7) / 8);

	return 0;
}

int sponge_absorb_final(sponge *sp)
{
	assert(sp != NULL);

	struct internals *internal = (struct internals *) sp->internal;

	/* Apply padding and add last block. */
	while (sp->p->pf(sp->p, internal->remaining, internal->remaining_bits)) {
		xor_and_permute_block(internal->state, sp->rate, sp->f, internal->remaining);
	}

	memset(internal->remaining, 0, sp->rate / 8);
	internal->remaining_bits = 0;

	return 0;
}

int sponge_squeeze(sponge *sp, unsigned char *output, const size_t output_bit_len)
{
	assert(sp != NULL && output != NULL);

	if (output_bit_len > sp->f->width || output_bit_len % 8 != 0) {
		return 1;
	}

	struct internals *internal = (struct internals *) sp->internal;

	memcpy(output, internal->state, output_bit_len / 8);

	return 0;
}
