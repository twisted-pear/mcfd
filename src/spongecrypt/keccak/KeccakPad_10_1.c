#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <keccak/KeccakPad_10_1.h>

static int pf(pad *p, permutation *f, const size_t remaining_bits);

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
	p->internal = NULL;

	return p;
}

void keccakPad_10_1_free(pad *p)
{
	free(p);
}

static int pf(pad *p, permutation *f, const size_t remaining_bits)
{
	if (p == NULL || f == NULL) {
		return 1;
	}

	if (p->rate >= f->width) {
		return 1;
	}

	if (remaining_bits >= p->rate) {
		return 1;
	}

	unsigned char pad_start_byte = 0x80;
	if (f->xor(f, (remaining_bits / 8) * 8, &pad_start_byte,
				(remaining_bits % 8) + 1) != 0) {
		return 1;
	}

	if (remaining_bits + 1 == p->rate) {
		f->f(f);
	}

	unsigned char pad_end_byte = 0x80;
	if (f->xor(f, (((p->rate + 7) / 8) - 1) * 8, &pad_end_byte,
				((p->rate + 7) % 8) + 1) != 0) {
		return 1;
	}

	f->f(f);

	return 0;
}
