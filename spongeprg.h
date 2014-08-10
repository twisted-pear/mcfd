#ifndef __SPONGEPRG_H__
#define __SPONGEPRG_H__

#include <stdint.h>

#include "pad.h"
#include "permutation.h"

typedef struct spongeprg_t {
	permutation *f;
	pad *p;
	size_t rate;
	size_t block_size;
	void *internal;
} spongeprg;

spongeprg *spongeprg_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size);
void spongeprg_free(spongeprg *g);

int spongeprg_feed(spongeprg *g, const unsigned char *in, const size_t in_byte_len);
int spongeprg_fetch(spongeprg *g, unsigned char *out, const size_t out_byte_len);
int spongeprg_forget(spongeprg *g);

#endif /* __SPONGEPRG_H__ */
