#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "spongewrap.h"
#include "duplex.h"

struct internals {
	duplex *dp;
	unsigned char *buf;
};

static int duplex_with_frame_bit(spongewrap *w, const unsigned char *in,
		const size_t in_byte_len, unsigned char *out,
		const size_t out_byte_len, bool frame_bit)
{
	assert(w != NULL);
	assert(in != NULL || in_byte_len == 0);
	assert(out != NULL || out_byte_len == 0);
	assert(in_byte_len <= w->block_size);

	struct internals *internal = (struct internals *) w->internal;
	assert(internal != NULL);

	/* FIXME: probably useless */
	memset(internal->buf, 0, w->block_size + 1);

	memcpy(internal->buf, in, in_byte_len);

	internal->buf[in_byte_len] = frame_bit ? 0x80 : 0x00;

	return duplex_duplexing(internal->dp, internal->buf, (in_byte_len + 1) * 8, out,
			out_byte_len * 8);
}

spongewrap *spongewrap_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size, const unsigned char *key,
		const size_t key_byte_len)
{
	assert(f != NULL && p != NULL);
	assert(key != NULL);

	if (block_size % 8 != 0 || block_size == 0) {
		return NULL;
	}

	if (key_byte_len == 0) {
		return NULL;
	}

	spongewrap *w = malloc(sizeof(spongewrap));
	if (w == NULL) {
		return NULL;
	}

	duplex *dp = duplex_init(f, p, rate);
	if (dp == NULL) {
		free(w);
		return NULL;
	}

	if (block_size >= dp->max_duplex_rate) {
		free(w);
		duplex_free(dp);
		return NULL;
	}

	unsigned char *buf = calloc(block_size + 1, 1);
	if (buf == NULL) {
		free(w);
		duplex_free(dp);
		return NULL;
	}

	struct internals *internal = malloc(sizeof(struct internals));
	if (internal == NULL) {
		free(buf);
		free(w);
		duplex_free(dp);
		return NULL;
	}

	internal->dp = dp;
	internal->buf = buf;

	w->f = f;
	w->p = p;
	w->rate = rate;
	w->block_size = block_size;
	w->internal = internal;

	size_t bytes_remaining = key_byte_len;

	const unsigned char *k = key;
	while (bytes_remaining > block_size) {
		if (duplex_with_frame_bit(w, k, block_size, NULL, 0, true) != 0) {
			spongewrap_free(w);
			return NULL;
		}

		bytes_remaining -= block_size;
		k += block_size;
	}

	if (duplex_with_frame_bit(w, k, bytes_remaining, NULL, 0, false) != 0) {
		spongewrap_free(w);
		return NULL;
	}

	return w;
}

void spongewrap_free(spongewrap *w)
{
	assert(w != NULL);
	assert(w->internal != NULL);

	struct internals *internal = (struct internals *) w->internal;

	duplex *dp = (duplex *) w->internal;
	duplex_free(dp);

	free(internal->buf);
	free(internal);

	free(w);
}

int spongewrap_wrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *b, const size_t b_byte_len, unsigned char *c,
		unsigned char *t, const size_t t_byte_len)
{
	return 1;
}

int spongewrap_unwrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *c, const size_t c_byte_len, const unsigned char *t,
		const size_t t_byte_len, unsigned char *b)
{
	return 1;
}
