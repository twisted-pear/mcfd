#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <keccak/KeccakF-1600.h>

#include "crypto_helpers.h"

#include "KeccakF-1600-interface.h"

#define L 6
#define W 64 /* 2^L */
#define NUM_ROUNDS (12 + 2 * L) /* 24 */
#define RC_WIDTH (5)
#define NUM_LANES (RC_WIDTH * RC_WIDTH) /* 25 */
#define PERMUTATION_WIDTH (NUM_LANES * W) /* 1600 */

static void f(permutation *p);

static int xor(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor576(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor832(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor1024(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor1088(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor1152(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int xor1344(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);

static int get(permutation *p, const size_t start_bit_idx, unsigned char *output,
		const size_t output_bit_len);

struct internals {
	unsigned char *state;
	unsigned char *copy_buf;
	size_t lanes;
};

static int initialized = 0;

permutation *keccakF_1600_init(size_t rate_hint)
{
	if (initialized == 0) {
		KeccakInitialize();
		initialized = 1;
	}

	if (rate_hint > PERMUTATION_WIDTH) {
		return NULL;
	}

	permutation *p = malloc(sizeof(permutation));
	if (p == NULL) {
		return NULL;
	}

	p->internal = malloc(sizeof(struct internals));
	if (p->internal == NULL) {
		free(p);
		return NULL;
	}

	struct internals *internal = (struct internals *) p->internal;

	internal->state = calloc(PERMUTATION_WIDTH / 8, 1);
	if (internal->state == NULL) {
		free(internal);
		free(p);
		return NULL;
	}

	KeccakInitializeState(internal->state);

	p->width = PERMUTATION_WIDTH;
	p->f = f;
	p->xor = xor;
	p->get = get;

	/* The Keccak interface requires the number of lanes. */
	if (rate_hint == 0) {
		internal->lanes = NUM_LANES;
	} else {
		internal->lanes = (rate_hint + (W - 1)) / W;
	}

	assert(internal->lanes <= NUM_LANES);

	internal->copy_buf = calloc((internal->lanes * W) / 8, 1);
	if (internal->copy_buf == NULL) {
		free(internal->state);
		free(internal);
		free(p);
		return NULL;
	}

	switch (rate_hint) {
	case 576:
		p->xor = xor576;
		break;
	case 832:
		p->xor = xor832;
		break;
	case 1024:
		p->xor = xor1024;
		break;
	case 1088:
		p->xor = xor1088;
		break;
	case 1152:
		p->xor = xor1152;
		break;
	case 1344:
		p->xor = xor1344;
		break;
	default:
		/* empty */
		break;
	}

	return p;
}

void keccakF_1600_free(permutation *p)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	struct internals *internal = (struct internals *) p->internal;

	explicit_bzero(internal->state, p->width / 8);
	free(internal->state);

	if (internal->copy_buf != NULL) {
		explicit_bzero(internal->copy_buf, (internal->lanes * W) / 8);
		free(internal->copy_buf);
	}

	internal->lanes = 0;

	free(internal);

	free(p);
}

static void f(permutation *p)
{
	/* Empty because in the used implementation xor and permute are done in absorb. */
}

static int xor(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert((input != NULL) | (input_bit_len == 0));

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx % 8 != 0) {
		return 1;
	}

	size_t buf_size = (internal->lanes * W) / 8;
	assert(buf_size <= p->width / 8);

	size_t si = start_bit_idx / 8;

	if (si >= buf_size) {
		return 1;
	}

	if (buf_size - si < (input_bit_len + 7) / 8) {
		return 1;
	}

	unsigned char *buf = internal->copy_buf;
	memset(buf, 0, si);

	size_t input_byte_len = input_bit_len / 8;
	memcpy(buf + si, input, input_byte_len);
	si += input_byte_len;

	memset(buf + si, 0, buf_size - si);

	/* Handle the last byte and make sure we only use the relevant bits. */
	size_t remaining_bits = input_bit_len % 8;
	if (remaining_bits != 0) {
		assert(si < buf_size);

		unsigned char last_byte = input[input_byte_len];
		last_byte &= (1 << remaining_bits) - 1;
		buf[si] = last_byte;
	}

	KeccakAbsorb(internal->state, buf, internal->lanes);

	return 0;
}

static int xor576(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 576) {
		return 1;
	}

	KeccakAbsorb576bits(internal->state, input);

	return 0;
}

static int xor832(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 832) {
		return 1;
	}

	KeccakAbsorb832bits(internal->state, input);

	return 0;
}

static int xor1024(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 1024) {
		return 1;
	}

	KeccakAbsorb1024bits(internal->state, input);

	return 0;
}

static int xor1088(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 1088) {
		return 1;
	}

	KeccakAbsorb1088bits(internal->state, input);

	return 0;
}

static int xor1152(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 1152) {
		return 1;
	}

	KeccakAbsorb1152bits(internal->state, input);

	return 0;
}

static int xor1344(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert(input != NULL);

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx != 0 || input_bit_len != 1344) {
		return 1;
	}

	KeccakAbsorb1344bits(internal->state, input);

	return 0;
}


static int get(permutation *p, const size_t start_bit_idx, unsigned char *output,
		const size_t output_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert((output != NULL) | (output_bit_len == 0));

	struct internals *internal = (struct internals *) p->internal;

	assert(internal->copy_buf != NULL);
	assert(internal->lanes > 0);

	if (start_bit_idx % 8 != 0) {
		return 1;
	}

	size_t buf_size = (internal->lanes * W) / 8;
	assert(buf_size <= p->width / 8);

	size_t si = start_bit_idx / 8;

	if (si >= buf_size) {
		return 1;
	}

	if (buf_size - si < (output_bit_len + 7) / 8) {
		return 1;
	}

	if (start_bit_idx == 0 && output_bit_len == 1024) {
		KeccakExtract1024bits(internal->state, output);
		return 0;
	}

	unsigned char *buf = internal->copy_buf;
	KeccakExtract(internal->state, buf, internal->lanes);

	size_t output_byte_len = output_bit_len / 8;
	assert(output_byte_len <= buf_size - si);

	memcpy(output, buf + si, output_byte_len);

	size_t remaining_bits = output_bit_len % 8;
	if (remaining_bits != 0) {
		assert(si + output_byte_len < buf_size);

		unsigned char last_byte = buf[si + output_byte_len];
		last_byte <<= 8 - remaining_bits;
		output[output_byte_len] = last_byte;
	}

	return 0;
}
