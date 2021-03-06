#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "crypto_helpers.h"

void explicit_bzero(void *s, const size_t n)
{
	memset(s, 0, n);
}

int timingsafe_bcmp(const void *s1, const void *s2, const size_t n)
{
	const unsigned char *a = s1;
	const unsigned char *b = s2;
	unsigned char ret = 0;

	size_t i;
	for (i = 0; i < n; i++) {
		ret |= a[i] ^ b[i];
	}

	return (ret != 0);
}
