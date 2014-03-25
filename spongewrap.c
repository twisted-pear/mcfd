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

#include <stdio.h>
static void print_buf(const unsigned char *buf, size_t len)
{
	size_t i;

	printf("\n");
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static void duplex_with_frame_bit(spongewrap *w, const unsigned char *in,
		const size_t in_byte_len, unsigned char *out,
		const size_t out_byte_len, bool frame_bit)
{
	assert(w != NULL);
	assert(in != NULL || in_byte_len == 0);
	assert(out != NULL || out_byte_len == 0);
	assert(in_byte_len <= w->block_size);
	assert(out_byte_len <= w->block_size);

	struct internals *internal = (struct internals *) w->internal;
	assert(internal != NULL);

	/* FIXME: probably useless */
	memset(internal->buf, 0, w->block_size + 1);

	memcpy(internal->buf, in, in_byte_len);

	internal->buf[in_byte_len] = frame_bit ? 0x80 : 0x00;

	//print_buf(internal->buf, w->block_size + 1);

	if (duplex_duplexing(internal->dp, internal->buf, (in_byte_len * 8) + 1, out,
				out_byte_len * 8) != 0) {
		assert(0);
	}
}

spongewrap *spongewrap_init(permutation *f, pad *p, const size_t rate,
		const size_t block_size, const unsigned char *key,
		const size_t key_byte_len)
{
	assert(f != NULL && p != NULL);
	assert(key != NULL);

	if (block_size == 0) {
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

	if (block_size * 8 >= dp->max_duplex_rate) {
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
		duplex_with_frame_bit(w, k, block_size, NULL, 0, true);

		bytes_remaining -= block_size;
		k += block_size;
	}

	duplex_with_frame_bit(w, k, bytes_remaining, NULL, 0, false);

	return w;
}

void spongewrap_free(spongewrap *w)
{
	assert(w != NULL);
	assert(w->internal != NULL);

	struct internals *internal = (struct internals *) w->internal;

	duplex_free(internal->dp);
	free(internal->buf);
	free(internal);

	free(w);
}

int spongewrap_wrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *b, const size_t b_byte_len, unsigned char *c,
		unsigned char *t, const size_t t_byte_len)
{
	assert(w != NULL);
	assert(a != NULL || a_byte_len == 0);
	assert(b != NULL || b_byte_len == 0);
	assert(c != NULL || b_byte_len == 0);
	assert(t != NULL || t_byte_len == 0);
	assert(b != c || b == NULL);

	size_t i;
	size_t block_size = w->block_size;

	/* Duplex header */
	size_t a_remaining = a_byte_len;
	const unsigned char *a_cur = a;
	while (a_remaining > block_size) {
		duplex_with_frame_bit(w, a_cur, block_size, NULL, 0, false);

		a_remaining -= block_size;
		a_cur += block_size;
	}

	/* Duplex last header block and get key for first crypto block. */
	size_t b_next_len = b_byte_len < block_size ? b_byte_len : block_size;
	duplex_with_frame_bit(w, a_cur, a_remaining, c, b_next_len, true);

	/* XOR the plaintext with the key and then duplex it to get the next key. */
	size_t b_remaining = b_byte_len;
	const unsigned char *b_cur = b;
	unsigned char *c_cur = c;
	while (b_remaining > block_size) {
		assert(b_next_len == block_size);
		assert(c_cur - c == b_cur - b);

		for (i = 0; i < block_size; i++) {
			c_cur[i] ^= b_cur[i];
		}

		c_cur += block_size;
		b_remaining -= block_size;

		b_next_len = b_remaining < block_size ? b_remaining : block_size;

		duplex_with_frame_bit(w, b_cur, block_size, c_cur, b_next_len, true);

		b_cur += block_size;
	}

	/* XOR last block of the plaintext with the key and get first part of the tag. */
	assert(b_next_len == b_remaining);
	assert(c_cur - c == b_cur - b);

	for (i = 0; i < b_remaining; i++) {
		c_cur[i] ^= b_cur[i];
	}

	size_t t_next_len = t_byte_len < block_size ? t_byte_len : block_size;
	duplex_with_frame_bit(w, b_cur, b_remaining, t, t_next_len, false);

	/* Obtain the remainder of the tag. */
	size_t t_remaining = t_byte_len - t_next_len;
	unsigned char *t_cur = t + t_next_len;
	while (t_remaining > block_size) {
		duplex_with_frame_bit(w, NULL, 0, t_cur, block_size, false);

		t_remaining -= block_size;
		t_cur += block_size;
	}

	if (t_remaining != 0) {
		duplex_with_frame_bit(w, NULL, 0, t_cur, t_remaining, false);
	}

	/* Just in case. */
	unsigned char *buf = ((struct internals *) w->internal)->buf;
	memset(buf, 0, block_size + 1);

	return 0;
}

int spongewrap_unwrap(spongewrap *w, const unsigned char *a, const size_t a_byte_len,
		const unsigned char *c, const size_t c_byte_len, const unsigned char *t,
		const size_t t_byte_len, unsigned char *b)
{
	assert(w != NULL);
	assert(a != NULL || a_byte_len == 0);
	assert(b != NULL || c_byte_len == 0);
	assert(c != NULL || c_byte_len == 0);
	assert(t != NULL || t_byte_len == 0);
	assert(b != c || b == NULL);

	size_t i;
	size_t block_size = w->block_size;
	int ret = 1;

	/* Duplex header */
	size_t a_remaining = a_byte_len;
	const unsigned char *a_cur = a;
	while (a_remaining > block_size) {
		duplex_with_frame_bit(w, a_cur, block_size, NULL, 0, false);

		a_remaining -= block_size;
		a_cur += block_size;
	}

	/* Duplex last header block and get key for first crypto block. */
	size_t c_next_len = c_byte_len < block_size ? c_byte_len : block_size;
	duplex_with_frame_bit(w, a_cur, a_remaining, b, c_next_len, true);

	/* XOR the ciphertext with the key to obtain the plaintext and then duplex that
	 * to get the next key. */
	size_t c_remaining = c_byte_len;
	const unsigned char *c_cur = c;
	unsigned char *b_cur = b;
	while (c_remaining > block_size) {
		assert(c_next_len == block_size);
		assert(c_cur - c == b_cur - b);

		for (i = 0; i < block_size; i++) {
			b_cur[i] ^= c_cur[i];
		}

		c_cur += block_size;
		c_remaining -= block_size;

		c_next_len = c_remaining < block_size ? c_remaining : block_size;

		duplex_with_frame_bit(w, b_cur, block_size, b_cur + block_size,
				c_next_len, true);

		b_cur += block_size;
	}

	/* Get last block of the plaintext and check the first part of the tag. */
	assert(c_next_len == c_remaining);
	assert(c_cur - c == b_cur - b);

	for (i = 0; i < c_remaining; i++) {
		b_cur[i] ^= c_cur[i];
	}

	/* We can write to the internal buffer because duplex_with_frame_bit() allows
	 * this. */
	unsigned char *buf = ((struct internals *) w->internal)->buf;

	size_t t_next_len = t_byte_len < block_size ? t_byte_len : block_size;
	duplex_with_frame_bit(w, b_cur, c_remaining, buf, t_next_len, false);

	if (memcmp(t, buf, t_next_len) != 0) {
		goto fail;
	}

	/* Check the remainder of the tag. */
	size_t t_remaining = t_byte_len - t_next_len;
	const unsigned char *t_cur = t + t_next_len;
	while (t_remaining > block_size) {
		duplex_with_frame_bit(w, NULL, 0, buf, block_size, false);

		if (memcmp(t_cur, buf, block_size) != 0) {
			goto fail;
		}

		t_remaining -= block_size;
		t_cur += block_size;
	}

	if (t_remaining != 0) {
		duplex_with_frame_bit(w, NULL, 0, buf, t_remaining, false);

		if (memcmp(t_cur, buf, t_remaining) != 0) {
			goto fail;
		}
	}

	ret = 0;
	goto done;

fail:
	/* The computed tag was invalid.
	 * Note that w is useless now. */
	ret = 1;

	/* Destroy any plaintext we produced to make sure the caller doesn't use it. */
	memset(b, 0, c_byte_len);

done:
	/* Just in case. */
	memset(buf, 0, block_size + 1);

	return ret;
}
