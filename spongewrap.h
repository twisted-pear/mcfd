#ifndef __SPONGEWRAP_H__
#define __SPONGEWRAP_H__

#include <stdint.h>

#include "pad.h"
#include "permutation.h"

typedef struct spongewrap_t {
	permutation *f;
	pad *p;
	size_t rate;
	size_t block_size;
	void *internal;
} spongewrap;

spongewrap *spongewrap_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size, const unsigned char *key,
		const size_t key_byte_len);
void spongewrap_free(spongewrap *w);

int spongewrap_wrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *b, const size_t b_byte_len, unsigned char *c,
		unsigned char *t, const size_t t_byte_len);
int spongewrap_unwrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *c, const size_t c_byte_len, const unsigned char *t,
		const size_t t_byte_len, unsigned char *b);

#endif /* __SPONGEWRAP_H__ */
