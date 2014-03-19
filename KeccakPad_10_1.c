#include <stdlib.h>
#include <string.h>

#include "KeccakPad_10_1.h"

static int pf(pad *p, unsigned char *data, const size_t remaining_bits);

enum {
	PAD_READY = 0,
	PAD_STARTED,
	PAD_DONE
};

pad *keccakPad_10_1_init(const size_t rate)
{
	if (rate == 0 || rate % 8 != 0) {
		return NULL;
	}

	pad *p = malloc(sizeof(pad));
	if (p == NULL) {
		return NULL;
	}

	p->rate = rate;
	p->min_bit_len = 2;
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
	if (p->internal == (void *) PAD_DONE) {
		p->internal = (void *) PAD_READY;
		return 0;
	}

	if (p->internal == (void *) PAD_STARTED || remaining_bits == 0) {
		memset(data, 0, p->rate / 8);
		if (p->internal != (void *) PAD_STARTED) {
			data[0] = 0x01;
		}
	} else {
		size_t last_byte = remaining_bits / 8;
		size_t bits_in_last_byte = remaining_bits % 8;
		data[last_byte] >>= 8 - bits_in_last_byte;
		data[last_byte] |= 0x80 >> (7 - bits_in_last_byte);
		memset(data + last_byte + 1, 0, p->rate / 8 - (last_byte + 1));
	}

	if (remaining_bits + 1 == p->rate && p->internal != (void *) PAD_STARTED) {
		p->internal = (void *) PAD_STARTED;
		return 1;
	}

	data[p->rate / 8 - 1] |= 0x80;

	p->internal = (void *) PAD_DONE;

	return 1;
}
