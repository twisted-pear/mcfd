#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "KeccakPad_10_1.h"

static int pf(pad *p, unsigned char *data, const size_t remaining_bits);

enum {
	PAD_READY = 0,
	PAD_STARTED,
	PAD_DONE
};

pad *keccakPad_10_1_init(const size_t rate)
{
	if (rate < KECCAKPAD_10_1_MIN_BIT_LEN + 1) {
		return NULL;
	}

	pad *p = malloc(sizeof(pad));
	if (p == NULL) {
		return NULL;
	}

	p->rate = rate;
	p->min_bit_len = KECCAKPAD_10_1_MIN_BIT_LEN;
	p->pf = pf;
	p->internal = (void *) PAD_READY;

	return p;
}

void keccakPad_10_1_free(pad *p)
{
	free(p);
}

static int pf(pad *p, unsigned char *data, const size_t remaining_bits)
{
	assert(remaining_bits < p->rate);

	if (p->internal == (void *) PAD_DONE) {
		p->internal = (void *) PAD_READY;
		return 0;
	}

	size_t data_size = (p->rate + 7) / 8;

	if (p->internal == (void *) PAD_STARTED || remaining_bits == 0) {
		memset(data, 0, data_size);
		if (p->internal != (void *) PAD_STARTED) {
			data[0] = 0x01;
		}
	} else {
		size_t last_byte_idx = remaining_bits / 8;
		size_t bits_in_last_byte = remaining_bits % 8;
		data[last_byte_idx] >>= 8 - bits_in_last_byte;
		data[last_byte_idx] |= 0x80 >> (7 - bits_in_last_byte);
		memset(data + last_byte_idx + 1, 0, data_size - (last_byte_idx + 1));
	}

	if (remaining_bits + 1 == p->rate && p->internal != (void *) PAD_STARTED) {
		p->internal = (void *) PAD_STARTED;
		return 1;
	}

	size_t last_data_byte_idx = data_size - 1;
	size_t pad_end_bit = 1 << ((p->rate + 7) % 8);

	assert((data[last_data_byte_idx] & pad_end_bit) == 0);

	data[last_data_byte_idx] |= pad_end_bit;

	p->internal = (void *) PAD_DONE;

	return 1;
}
