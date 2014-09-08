#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "spongeprg.h"
#include "crypto_helpers.h"
#include "duplex.h"

struct internals {
	duplex *dp;
	unsigned char *buf;
	size_t bin_byte_len;
	size_t bout_byte_len;
};

static void spongeprg_clear_buffers(spongeprg *g)
{
	assert(g != NULL);
	assert(g->internal != NULL);

	struct internals *internal = (struct internals *) g->internal;

	duplex_clear_buffers(internal->dp);
	explicit_bzero(internal->buf, g->block_size);

	internal->bin_byte_len = 0;
	internal->bout_byte_len = 0;
}

spongeprg *spongeprg_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size)
{
	assert(f != NULL && p != NULL);

	if (block_size == 0) {
		return NULL;
	}

	spongeprg *g = malloc(sizeof(spongeprg));
	if (g == NULL) {
		return NULL;
	}

	duplex *dp = duplex_init(f, p, rate);
	if (dp == NULL) {
		free(g);
		return NULL;
	}

	if (block_size * 8 > dp->max_duplex_rate) {
		free(g);
		duplex_free(dp);
		return NULL;
	}

	unsigned char *buf = calloc(block_size, 1);
	if (buf == NULL) {
		free(g);
		duplex_free(dp);
		return NULL;
	}

	struct internals *internal = malloc(sizeof(struct internals));
	if (internal == NULL) {
		free(buf);
		free(g);
		duplex_free(dp);
		return NULL;
	}

	internal->dp = dp;
	internal->buf = buf;
	internal->bin_byte_len = 0;
	internal->bout_byte_len = 0;

	g->f = f;
	g->p = p;
	g->rate = rate;
	g->block_size = block_size;
	g->internal = internal;

	return g;
}

void spongeprg_free(spongeprg *g)
{
	assert(g != NULL);
	assert(g->internal != NULL);

	spongeprg_clear_buffers(g);

	struct internals *internal = (struct internals *) g->internal;

	duplex_free(internal->dp);
	free(internal->buf);

	free(internal);

	free(g);
}

int spongeprg_feed(spongeprg *g, const unsigned char *in, const size_t in_byte_len)
{
	assert(g != NULL);
	assert((in != NULL) | (in_byte_len == 0));

	size_t block_size = g->block_size;

	struct internals *internal = (struct internals *) g->internal;
	assert(internal != NULL);

	assert(internal->bin_byte_len < block_size);
	assert(internal->bout_byte_len < block_size);
	assert((internal->bin_byte_len == 0) | (internal->bout_byte_len == 0));

	size_t in_remaining = in_byte_len;
	const unsigned char *in_cur = in;

	/* Duplex in current bin if we can. */
	size_t bytes_to_block = block_size - internal->bin_byte_len;
	if (in_remaining >= bytes_to_block && internal->bin_byte_len != 0) {
		memcpy(internal->buf + internal->bin_byte_len, in_cur, bytes_to_block);
		if (duplex_duplexing(internal->dp, internal->buf, block_size * 8,
					NULL, 0) != CONSTR_SUCCESS) {
			assert(0);
		}

		explicit_bzero(internal->buf, block_size);
		internal->bin_byte_len = 0;

		in_remaining -= bytes_to_block;
		in_cur += bytes_to_block;
	}

	/* Duplex any full blocks we have. */
	while (in_remaining >= block_size) {
		assert(internal->bin_byte_len == 0);

		if (duplex_duplexing(internal->dp, in_cur, block_size * 8, NULL,
					0) != CONSTR_SUCCESS) {
			assert(0);
		}

		in_remaining -= block_size;
		in_cur += block_size;
	}

	/* Clear the duplex' buffers just in case. */
	duplex_clear_buffers(internal->dp);

	/* Clear bout. */
	if (internal->bout_byte_len != 0) {
		assert(internal->bin_byte_len == 0);

		explicit_bzero(internal->buf, block_size);
		internal->bout_byte_len = 0;
	}

	assert(in_remaining < (block_size - internal->bin_byte_len));

	/* Save remaining input in buffer. */
	memcpy(internal->buf + internal->bin_byte_len, in_cur, in_remaining);
	internal->bin_byte_len += in_remaining;

	assert(internal->bin_byte_len < block_size);
	assert(internal->bout_byte_len < block_size);
	assert((internal->bin_byte_len == 0) | (internal->bout_byte_len == 0));

	return 0;
}

int spongeprg_fetch(spongeprg *g, unsigned char *out, const size_t out_byte_len)
{
	assert(g != NULL);
	assert((out != NULL) | (out_byte_len == 0));

	size_t block_size = g->block_size;

	struct internals *internal = (struct internals *) g->internal;
	assert(internal != NULL);

	assert(internal->bin_byte_len < block_size);
	assert(internal->bout_byte_len < block_size);
	assert((internal->bin_byte_len == 0) | (internal->bout_byte_len == 0));

	size_t out_remaining = out_byte_len;
	unsigned char *out_cur = out;

	if (internal->bout_byte_len < out_remaining) {
		memcpy(out_cur, internal->buf, internal->bout_byte_len);
		out_remaining -= internal->bout_byte_len;
		out_cur += internal->bout_byte_len;
		internal->bout_byte_len = 0;

		/* Get as many full blocks as we need. */
		while (out_remaining > block_size) {

			if (duplex_duplexing(internal->dp, internal->buf,
						internal->bin_byte_len * 8, out_cur,
						block_size * 8) != CONSTR_SUCCESS) {
				assert(0);
			}

			internal->bin_byte_len = 0;

			out_remaining -= block_size;
			out_cur += block_size;
		}

		assert(out_remaining > 0);

		/* Get remaining output. */
		if (duplex_duplexing(internal->dp, internal->buf,
					internal->bin_byte_len * 8, internal->buf,
					block_size * 8) != CONSTR_SUCCESS) {
			assert(0);
		}
		internal->bout_byte_len = block_size;

		internal->bin_byte_len = 0;

		/* Clear the duplex' buffers just in case. */
		duplex_clear_buffers(internal->dp);
	}

	assert(out_remaining <= internal->bout_byte_len);

	if (internal->bout_byte_len > 0) {
		assert(internal->bin_byte_len == 0);

		memcpy(out_cur, internal->buf, out_remaining);

		/* Save any excess data in bout. */
		internal->bout_byte_len -= out_remaining;
		memcpy(internal->buf, internal->buf + out_remaining,
				internal->bout_byte_len);
		explicit_bzero(internal->buf + internal->bout_byte_len,
				block_size - internal->bout_byte_len);
	} else {
		assert(out_remaining == 0);
	}

	assert(internal->bin_byte_len < block_size);
	assert(internal->bout_byte_len < block_size);
	assert((internal->bin_byte_len == 0) | (internal->bout_byte_len == 0));

	return 0;
}

/* TODO: this requires block_size >= width - rate */
int spongeprg_forget(spongeprg *g)
{
	assert(g != NULL);

	size_t block_size = g->block_size;

	struct internals *internal = (struct internals *) g->internal;
	assert(internal != NULL);

	assert(internal->bin_byte_len < block_size);
	assert(internal->bout_byte_len < block_size);
	assert((internal->bin_byte_len == 0) | (internal->bout_byte_len == 0));

	if (duplex_duplexing(internal->dp, internal->buf, internal->bin_byte_len * 8,
				internal->buf, block_size * 8) != CONSTR_SUCCESS) {
		assert(0);
	}

	if (duplex_duplexing(internal->dp, internal->buf, block_size * 8, internal->buf,
				block_size * 8) != CONSTR_SUCCESS) {
		assert(0);
	}

	spongeprg_clear_buffers(g);

	assert(internal->bin_byte_len == 0);
	assert(internal->bout_byte_len == 0);

	return 0;
}
