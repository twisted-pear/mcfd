#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_getrandom
#	include <fcntl.h>
#endif /* SYS_getrandom */

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_random.h"

/* TODO: This should be replaced with a userspace PRNG that is seeded in
 * mcfd_random_init() and mcfd_random_reseed(). */

static_assert(MCFD_RANDOM_REQUEST_MAX < INT_MAX, "MCFD_RANDOM_REQUEST_MAX too large");

#ifdef SYS_getrandom

static int getrandom_get(unsigned char *outbuf, const size_t outbuf_size)
{
	if (outbuf_size > MCFD_RANDOM_REQUEST_MAX) {
		return 1;
	}

	int ret = 0;
	for (;;) {
		ret = syscall(SYS_getrandom, outbuf, outbuf_size, 0);
		if (ret >= 0) {
			break;
		}

		if (errno != EINTR) {
			return 1;
		}
	}

	assert(outbuf_size < INT_MAX);
	assert(ret >= 0);

	if (ret != (int) outbuf_size) {
		explicit_bzero(outbuf, outbuf_size);
		return 1;
	}

	return 0;
}

#else /* SYS_getrandom */

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

#endif /* SYS_getrandom */

int mcfd_random_init(void)
{
#ifndef SYS_getrandom
	return urandom_open();
#else /* SYS_getrandom */
	return 0;
#endif /* SYS_getrandom */
}

void mcfd_random_destroy(void)
{
#ifndef SYS_getrandom
	urandom_close();
#endif /* SYS_getrandom */
}

int mcfd_random_reseed(void)
{
	return 0;
}

int mcfd_random_get(unsigned char *outbuf, const size_t outbuf_size)
{
#ifndef SYS_getrandom
	return urandom_get(outbuf, outbuf_size);
#else /* SYS_getrandom */
	return getrandom_get(outbuf, outbuf_size);
#endif /* SYS_getrandom */
}
