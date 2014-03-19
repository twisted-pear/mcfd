#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "duplex.h"

#include "sponge.h"

duplex *duplex_init(permutation *f, pad *p, const size_t rate)
{
	assert(f != NULL && p != NULL);

	duplex *dp = malloc(sizeof(duplex));
	if (dp == NULL) {
		return NULL;
	}

	dp->f = f;
	dp->p = p;
	dp->rate = rate;

	sponge *sp = sponge_init(f, p, rate);
	if (sp == NULL) {
		free(dp);
		return NULL;
	}

	dp->internal = sp;

	return dp;
}

void duplex_free(duplex *dp)
{
	assert(dp != NULL);

	sponge *sp = (sponge *) dp->internal;
	sponge_free(sp);

	free(dp);
}

int duplex_duplexing(duplex *dp, const unsigned char *input, const size_t input_bit_len,
		unsigned char *output, const size_t output_bit_len)
{
	assert(dp != NULL);
	assert(input != NULL || input_bit_len == 0);
	assert(output != NULL || output_bit_len == 0);

	sponge *sp = (sponge *) dp->internal;

	assert(sp != NULL);

	if (input_bit_len > dp->rate - dp->p->min_bit_len) {
		return 1;
	}

	if (output_bit_len > dp->rate) {
		return 1;
	}

	if (input_bit_len != 0) {
		if (sponge_absorb(sp, input, input_bit_len) != 0) {
			return 1;
		}
	}

	if (sponge_absorb_final(sp) != 0) {
		return 1;
	}

	if (output_bit_len != 0) {
		if (sponge_squeeze(sp, output, output_bit_len) != 0) {
			return 1;
		}
	}

	return 0;
}
