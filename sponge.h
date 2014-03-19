#ifndef __SPONGE_H__
#define __SPONGE_H__

#include <stdint.h>

#include "pad.h"
#include "permutation.h"

typedef struct sponge_t {
	permutation *f;
	pad *p;
	size_t rate;
	void *internal;
} sponge;

sponge *sponge_init(permutation *f, pad *p, const size_t rate);
void sponge_free(sponge *sp);

int sponge_absorb(sponge *sp, const unsigned char *input, const size_t input_bit_len);
int sponge_absorb_final(sponge *sp);
int sponge_squeeze(sponge *sp, unsigned char *output, const size_t output_bit_len);

#endif /* __SPONGE_H__ */
