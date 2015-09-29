#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <assert.h>

#include "crypto_helpers.h"
#include "mcfd_random.h"

/* TODO: This should be replaced with a userspace PRNG that is seeded in
 * mcfd_random_init() and mcfd_random_reseed(). */

static_assert(MCFD_RANDOM_REQUEST_MAX < INT_MAX, "MCFD_RANDOM_REQUEST_MAX too large");

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

int mcfd_random_init(void)
{
	return 0;
}

void mcfd_random_destroy(void)
{
}

int mcfd_random_reseed(void)
{
	return 0;
}

int mcfd_random_get(unsigned char *outbuf, const size_t outbuf_size)
{
	return getrandom_get(outbuf, outbuf_size);
}
