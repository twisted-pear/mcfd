#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "sponge.h"
#include "crypto_helpers.h"

struct internals {
	unsigned char *remaining;
	size_t remaining_bits;
	size_t width;
	enum { PHASE_ABSORB = 0, PHASE_SQUEEZE } phase;
};

sponge *sponge_init(permutation *f, pad *p, const size_t rate)
{
	if (f == NULL || p == NULL) {
		return NULL;
	}

	if (rate == 0 || f->width == 0) {
		return NULL;
	}

	if (rate >= f->width) {
		return NULL;
	}

	if (rate % 8 != 0 || f->width % 8 != 0) {
		return NULL;
	}

	if (rate <= p->min_bit_len) {
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

	internal->remaining = calloc(rate / 8, 1);
	if (internal->remaining == NULL) {
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

		if (sp->f->xor(sp->f, 0, internal->remaining, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);
	}

	/* Absorb full blocks in the input. */
	size_t remaining_bit_len = input_bit_len - bits_needed;
	const unsigned char *begin_full = input + bits_needed / 8;

	while (remaining_bit_len >= sp->rate) {
		if (sp->f->xor(sp->f, 0, begin_full, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

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
		if (sp->f->xor(sp->f, 0, internal->remaining, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);
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

	assert(internal->remaining_bits % 8 == 0);

	/* Don't allow squeezing partial bytes.
	 * Rationale: The reference implementation doesn't allow this either (and it's easier). */
	if (output_bit_len % 8 != 0) {
		return 1;
	}

	size_t bits_needed = output_bit_len;
	unsigned char *current_out = output;

	/* Hand out old data first. */
	if (internal->remaining_bits != 0) {
		assert(internal->remaining_bits < sp->rate);

		unsigned char *remaining_start = internal->remaining + (sp->rate -
			internal->remaining_bits) / 8;
		if (internal->remaining_bits >= output_bit_len) {
			memcpy(output, remaining_start, output_bit_len / 8);
			internal->remaining_bits -= output_bit_len;
			return 0;
		} else {
			memcpy(output, remaining_start, internal->remaining_bits / 8);
			bits_needed -= internal->remaining_bits;
			current_out += internal->remaining_bits / 8;
			internal->remaining_bits = 0;
		}
	}

	assert(internal->remaining_bits == 0);
	assert(bits_needed > 0);

	while (bits_needed > sp->rate) {
		/* This works because (rate % 8 == 0). */
		if(sp->f->get(sp->f, 0, current_out, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

		bits_needed -= sp->rate;
		current_out += sp->rate / 8;
	}

	if (sp->f->get(sp->f, 0, internal->remaining, sp->rate) != 0) {
		assert(0);
	}
	sp->f->f(sp->f);

	assert(bits_needed % 8 == 0);
	assert(bits_needed <= sp->rate);

	memcpy(current_out, internal->remaining, bits_needed / 8);
	internal->remaining_bits = sp->rate - bits_needed;

	return 0;
}
