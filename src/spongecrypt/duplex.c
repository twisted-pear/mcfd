#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "duplex.h"
#include "crypto_helpers.h"

typedef enum {
	DUPLEX_READY = 0,
	DUPLEX_BROKEN
} duplex_state;

duplex *duplex_init(permutation *f, pad *p, const size_t rate)
{
	if (f == NULL || p == NULL) {
		return NULL;
	}

	if (f->width == 0) {
		return NULL;
	}

	if (f->width % 8 != 0) {
		return NULL;
	}

	if (rate >= f->width) {
		return NULL;
	}

	if (rate <= p->min_bit_len) {
		return NULL;
	}

	if (p->rate != rate) {
		return NULL;
	}

	duplex *dp = malloc(sizeof(duplex));
	if (dp == NULL) {
		return NULL;
	}

	dp->f = f;
	dp->p = p;
	dp->rate = rate;
	dp->max_duplex_rate = rate - p->min_bit_len;

	dp->internal = (void *) DUPLEX_READY;

	return dp;
}

void duplex_free(duplex *dp)
{
	assert(dp != NULL);

	/* we don't want broken programs to use the freed duplex */
	dp->internal = (void *) DUPLEX_BROKEN;

	free(dp);
}

constr_result duplex_duplexing(duplex *dp, const unsigned char *input,
		const size_t input_bit_len, unsigned char *output,
		const size_t output_bit_len)
{
	if (dp == NULL) {
		return CONSTR_FAILURE;
	}

	if (dp->internal != DUPLEX_READY) {
		return CONSTR_FATAL;
	}

	if ((input == NULL) & (input_bit_len != 0)) {
		return CONSTR_FAILURE;
	}
	if ((output == NULL) & (output_bit_len != 0)) {
		return CONSTR_FAILURE;
	}

	if (input_bit_len > dp->max_duplex_rate) {
		return CONSTR_FAILURE;
	}

	if (output_bit_len > dp->rate) {
		return CONSTR_FAILURE;
	}

	/* Apply padding and add last block. */
	if (dp->f->xor(dp->f, 0, input, input_bit_len) != 0) {
		dp->internal = (void *) DUPLEX_BROKEN;
		return CONSTR_FATAL;
	}
	if (dp->p->pf(dp->p, dp->f, input_bit_len) != 0) {
		dp->internal = (void *) DUPLEX_BROKEN;
		return CONSTR_FATAL;
	}

	if (dp->f->get(dp->f, 0, output, output_bit_len) != 0) {
		dp->internal = (void *) DUPLEX_BROKEN;
		return CONSTR_FATAL;
	}

	return CONSTR_SUCCESS;
}
