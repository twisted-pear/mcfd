#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "sponge.h"
#include "crypto_helpers.h"

struct internals {
	unsigned char *state;
	unsigned char *remaining;
	size_t remaining_bits;
	size_t width;
	enum { PHASE_ABSORB = 0, PHASE_SQUEEZE } phase;
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

	internal->width = f->width;

	internal->phase = PHASE_ABSORB;

	return sp;
}

void sponge_free(sponge *sp)
{
	assert(sp != NULL);
	assert(sp->internal != NULL);

	struct internals *internal = (struct internals *) sp->internal;

	explicit_bzero(internal->state, internal->width / 8);
	free(internal->state);

	explicit_bzero(internal->remaining, sp->rate / 8);
	free(internal->remaining);

	internal->remaining_bits = 0;

	free(internal);

	free(sp);
}

int sponge_absorb(sponge *sp, const unsigned char *input, const size_t input_bit_len)
{
	assert((sp != NULL) & (input != NULL));

	struct internals *internal = (struct internals *) sp->internal;

	assert(internal->remaining_bits < sp->rate);

	/* Only absorb in absorb phase. */
	if (internal->phase != PHASE_ABSORB) {
		return 1;
	}

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

	/* Only absorb in absorb phase. */
	if (internal->phase != PHASE_ABSORB) {
		return 1;
	}

	/* Apply padding and add last block. */
	while (sp->p->pf(sp->p, internal->remaining, internal->remaining_bits)) {
		xor_and_permute_block(internal->state, sp->rate, sp->f, internal->remaining);
	}

	explicit_bzero(internal->remaining, sp->rate / 8);
	internal->remaining_bits = 0;

	/* Switch to squeezing. */
	internal->phase = PHASE_SQUEEZE;

	return 0;
}

int sponge_squeeze(sponge *sp, unsigned char *output, const size_t output_bit_len)
{
	assert((sp != NULL) & (output != NULL));

	struct internals *internal = (struct internals *) sp->internal;

	/* Only squeeze in squeeze phase. */
	if (internal->phase != PHASE_SQUEEZE) {
		return 1;
	}

	size_t bytes_needed = output_bit_len / 8;
	size_t rate_size_bytes = sp->rate / 8;

	unsigned char *current_out = output;
	while (bytes_needed >= rate_size_bytes) {
		/* This works because (rate % 8 == 0). */
		memcpy(current_out, internal->state, rate_size_bytes);
		sp->f->f(sp->f, internal->state);

		bytes_needed -= rate_size_bytes;
		current_out += rate_size_bytes;
	}

	memcpy(current_out, internal->state, bytes_needed);
	current_out += bytes_needed;
	
	size_t remaining_bits = output_bit_len % 8;
	if (remaining_bits != 0) {
		unsigned char last_byte = internal->state[bytes_needed];
		last_byte <<= 8 - remaining_bits;
		*current_out = last_byte;
	}

	return 0;
}
