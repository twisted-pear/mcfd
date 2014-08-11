#ifndef __DUPLEX_H__
#define __DUPLEX_H__

#include <stdint.h>

#include "pad.h"
#include "permutation.h"

typedef struct duplex_t {
	permutation *f;
	pad *p;
	size_t rate;
	size_t max_duplex_rate;
	void *internal;
} duplex;

duplex *duplex_init(permutation *f, pad *p, const size_t rate);
void duplex_free(duplex *dp);

void duplex_clear_buffers(duplex *dp);

int duplex_duplexing(duplex *dp, const unsigned char *input, const size_t input_bit_len,
		unsigned char *output, const size_t output_bit_len);

#endif /* __DUPLEX_H__ */
