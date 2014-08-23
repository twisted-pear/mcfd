#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "sponge.h"
#include "crypto_helpers.h"

struct internals {
	size_t remaining_bits;
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

	internal->remaining_bits = 0;

	internal->phase = PHASE_ABSORB;

	return sp;
}

void sponge_free(sponge *sp)
{
	assert(sp != NULL);
	assert(sp->internal != NULL);

	struct internals *internal = (struct internals *) sp->internal;

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
	 * Rationale: The reference implementation doesn't allow this either (and it's
	 * easier). */
	if (internal->remaining_bits % 8 != 0) {
		return 1;
	}

	size_t in_remaining = input_bit_len;
	const unsigned char *in_cur = input;

	/* Finish absorbing any started block from a previous sponge_absorb. */
	size_t bits_to_block = sp->rate - internal->remaining_bits;
	if (in_remaining >= bits_to_block && internal->remaining_bits != 0) {
		assert(bits_to_block % 8 == 0);

		if (sp->f->xor(sp->f, internal->remaining_bits, in_cur,
					bits_to_block) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

		internal->remaining_bits = 0;

		in_remaining -= bits_to_block;
		in_cur += bits_to_block / 8;
	}

	/* Absorb full blocks in the input. */
	while (in_remaining >= sp->rate) {
		assert(internal->remaining_bits == 0);

		if (sp->f->xor(sp->f, 0, in_cur, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

		in_remaining -= sp->rate;
		in_cur += sp->rate / 8;
	}

	/* Xor in the remainder but don't permute yet. */
	if (sp->f->xor(sp->f, internal->remaining_bits, in_cur, in_remaining) != 0) {
		assert(0);
	}

	internal->remaining_bits += in_remaining;

	assert(internal->remaining_bits < sp->rate);
	assert(internal->phase == PHASE_ABSORB);

	return 0;
}

int sponge_absorb_final(sponge *sp)
{
	assert(sp != NULL);

	struct internals *internal = (struct internals *) sp->internal;

	assert(internal->remaining_bits < sp->rate);

	/* Only absorb in absorb phase. */
	if (internal->phase != PHASE_ABSORB) {
		return 1;
	}

	/* Apply padding and permute last block(s). */
	if (sp->p->pf(sp->p, sp->f, internal->remaining_bits) != 0) {
		assert(0);
	}

	internal->remaining_bits = sp->rate;

	/* Switch to squeezing. */
	internal->phase = PHASE_SQUEEZE;

	assert(internal->remaining_bits <= sp->rate);
	assert(internal->remaining_bits % 8 == 0);
	assert(internal->remaining_bits != 0);

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

	assert(internal->remaining_bits <= sp->rate);
	assert(internal->remaining_bits % 8 == 0);
	assert(internal->remaining_bits != 0);

	/* Don't allow squeezing partial bytes.
	 * Rationale: The reference implementation doesn't allow this either (and it's
	 * easier). */
	if (output_bit_len % 8 != 0) {
		return 1;
	}

	size_t out_remaining = output_bit_len;
	unsigned char *out_cur = output;

	/* Hand out old data first. */
	if (internal->remaining_bits <= out_remaining) {
		size_t remaining_start = sp->rate - internal->remaining_bits;
		if(sp->f->get(sp->f, remaining_start, out_cur,
					internal->remaining_bits) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

		out_remaining -= internal->remaining_bits;
		out_cur += internal->remaining_bits / 8;

		internal->remaining_bits = sp->rate;
	}

	/* Get as many full blocks as we need. */
	while (out_remaining >= sp->rate) {
		assert(internal->remaining_bits == sp->rate);

		if (sp->f->get(sp->f, 0, out_cur, sp->rate) != 0) {
			assert(0);
		}
		sp->f->f(sp->f);

		out_remaining -= sp->rate;
		out_cur += sp->rate / 8;
	}

	assert(out_remaining < internal->remaining_bits);
	assert(out_remaining < sp->rate);

	size_t remaining_start = sp->rate - internal->remaining_bits;
	if (sp->f->get(sp->f, remaining_start, out_cur, out_remaining) != 0) {
		assert(0);
	}

	internal->remaining_bits -= out_remaining;

	assert(internal->remaining_bits <= sp->rate);
	assert(internal->remaining_bits % 8 == 0);
	assert(internal->remaining_bits != 0);
	assert(internal->phase == PHASE_SQUEEZE);

	return 0;
}
