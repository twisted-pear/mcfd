#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_random.h"

/* TODO: This should be replaced with a real PRNG. */

#define RANDBUF_SIZE MCFD_RANDOM_MAX
static unsigned char randbuf[RANDBUF_SIZE];
static unsigned char *rand_cur = randbuf + RANDBUF_SIZE;

static int urandom_fd = -1;

static int urandom_open(void)
{
	assert(urandom_fd == -1);

	for (;;) {
		urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd >= 0) {
			break;
		}

		if (errno != EINTR) {
			return 1;
		}
	}

	assert(urandom_fd >= 0);

	return 0;
}

static void urandom_close(void)
{
	if (urandom_fd != -1) {
		close(urandom_fd);
		urandom_fd = -1;
	}
}

static int urandom_get(unsigned char *outbuf, const size_t outbuf_size)
{
	if (urandom_fd == -1) {
		return 1;
	}

	if (outbuf == NULL) {
		return 1;
	}

	if (outbuf_size > SSIZE_MAX || outbuf_size == 0) {
		return 1;
	}

	size_t bytes_needed = outbuf_size;
	unsigned char *cur_outbuf = outbuf;
	ssize_t nread = 0;
	while (bytes_needed > 0) {
		nread = read(urandom_fd, cur_outbuf, bytes_needed);
		if (nread < 0) {
			if (errno != EINTR) {
				goto fail_read;
			}

			continue;
		}

		/* EOF? */
		if (nread == 0) {
			goto fail_read;
		}

		assert(bytes_needed <= SSIZE_MAX);
		assert(nread > 0);
		assert(nread <= (ssize_t) bytes_needed);

		bytes_needed -= nread;
		cur_outbuf += nread;
	}

	assert(bytes_needed == 0);
	assert(cur_outbuf == outbuf + outbuf_size);

	return 0;

fail_read:
	explicit_bzero(outbuf, outbuf_size);

	return 1;
}

int mcfd_random_init(void)
{
	assert((rand_cur >= randbuf) & (rand_cur <= randbuf + RANDBUF_SIZE));

	if (urandom_open() != 0) {
		return 1;
	}

	return mcfd_random_reseed();
}

void mcfd_random_destroy(void)
{
	assert((rand_cur >= randbuf) & (rand_cur <= randbuf + RANDBUF_SIZE));

	urandom_close();

	explicit_bzero(randbuf, RANDBUF_SIZE);
	rand_cur = randbuf + RANDBUF_SIZE;
}

int mcfd_random_reseed(void)
{
	assert((rand_cur >= randbuf) & (rand_cur <= randbuf + RANDBUF_SIZE));

	if (urandom_get(randbuf, RANDBUF_SIZE) != 0) {
		mcfd_random_destroy();
		return 1;
	}

	rand_cur = randbuf;

	return 0;
}

int mcfd_random_get(unsigned char *outbuf, const size_t outbuf_size)
{
	assert((rand_cur >= randbuf) & (rand_cur <= randbuf + RANDBUF_SIZE));

	if (outbuf == NULL) {
		return 1;
	}

	size_t rand_remaining = (randbuf + RANDBUF_SIZE) - rand_cur;

	if (outbuf_size > rand_remaining || outbuf_size == 0) {
		return 1;
	}

	memcpy(outbuf, rand_cur, outbuf_size);

	explicit_bzero(rand_cur, outbuf_size);
	rand_cur += outbuf_size;

	assert((rand_cur >= randbuf) & (rand_cur <= randbuf + RANDBUF_SIZE));

	return 0;
}
