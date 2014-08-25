#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <keccak/KeccakF-1600.h>

#include "crypto_helpers.h"

#define L 6
#define W 64 /* 2^L */
#define NUM_ROUNDS (12 + 2 * L) /* 24 */
#define RC_WIDTH (5)
#define NUM_LANES (RC_WIDTH * RC_WIDTH) /* 25 */
#define PERMUTATION_WIDTH (NUM_LANES * W) /* 1600 */

#define IDX(X,Y) ((RC_WIDTH * ((Y) % RC_WIDTH)) + ((X) % RC_WIDTH))

static void f(permutation *p);
static int xor(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len);
static int get(permutation *p, const size_t start_bit_idx, unsigned char *output,
		const size_t output_bit_len);

permutation *keccakF_1600_init(void)
{
	permutation *p = malloc(sizeof(permutation));
	if (p == NULL) {
		return NULL;
	}

	p->internal = calloc(PERMUTATION_WIDTH / 8, 1);
	if (p->internal == NULL) {
		free(p);
		return NULL;
	}

	p->width = PERMUTATION_WIDTH;
	p->f = f;
	p->xor = xor;
	p->get = get;

	return p;
}

void keccakF_1600_free(permutation *p)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	explicit_bzero(p->internal, p->width / 8);
	free(p->internal);

	free(p);
}

static uint64_t round_constants[NUM_ROUNDS] = {
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};

static int rho_constants[NUM_LANES] = {
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14
};

static void theta(uint64_t *state)
{
	int x,y;
	uint64_t c[RC_WIDTH];
	uint64_t d[RC_WIDTH];
	uint64_t tmp;

	for (x = 0; x < RC_WIDTH; x++) {
		c[x] = state[IDX(x,0)] ^ state[IDX(x,1)] ^ state[IDX(x,2)]
			^ state[IDX(x,3)] ^ state[IDX(x,4)];
	}

	for (x = 0; x < RC_WIDTH; x++) {
		tmp = c[(x + 1) % RC_WIDTH];
		d[x] = c[(x + 4) % RC_WIDTH] ^ ((tmp << 1) | (tmp >> (W - 1)));
	}

	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			state[IDX(x,y)] ^= d[x];
		}
	}
}

static void rho(uint64_t *state)
{
	int x,y;
	uint64_t tmp;
	int off;

	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			tmp = state[IDX(x,y)];
			off = rho_constants[IDX(x,y)];
			state[IDX(x,y)] = (tmp << off) | (tmp >> (W - off));
		}
	}
}

static void pi(uint64_t *state)
{
	uint64_t tmp[RC_WIDTH][RC_WIDTH];

	int x,y;
	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			tmp[y][(2 * x + 3 * y) % RC_WIDTH] = state[IDX(x,y)];
		}
	}

	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			state[IDX(x,y)] = tmp[x][y];
		}
	}
}

static void chi(uint64_t *state)
{
	uint64_t tmp[RC_WIDTH][RC_WIDTH];

	int x,y;
	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			tmp[x][y] = (~state[IDX(x + 1,y)]) & state[IDX(x + 2,y)];
		}
	}
	for (x = 0; x < RC_WIDTH; x++) {
		for (y = 0; y < RC_WIDTH; y++) {
			state[IDX(x,y)] ^= tmp[x][y];
		}
	}
}

static void iota(uint64_t *state, int round)
{
	state[IDX(0,0)] ^= round_constants[round];
}

static void print_state_lanes(uint64_t *state, int round)
{
	size_t i;

	printf("Round %d:\n", round);
	for (i = 0; i < NUM_LANES; i++) {
		printf("%016zx", state[i]);
		if (i % RC_WIDTH == 4) {
			printf("\n");
		} else {
			printf(" ");
		}
	}
	printf("\n");
}

static void print_state(const unsigned char *state, int round)
{
	size_t i;

	printf("Round %d:\n", round);
	for (i = 0; i < PERMUTATION_WIDTH / 8; i++) {
		printf("%02x ", state[i]);
	}
	printf("\n");
}

static void permute(permutation *p, unsigned char *state)
{
	assert(p != NULL);
	assert(state != NULL);

	uint64_t *state_as_lanes = (uint64_t *) state;

	int i;
	for (i = 0; i < NUM_ROUNDS; i++) {
		theta(state_as_lanes);
		rho(state_as_lanes);
		pi(state_as_lanes);
		chi(state_as_lanes);
		iota(state_as_lanes, i);
	}
}

static void f(permutation *p)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	permute(p, p->internal);
}

static int xor(permutation *p, const size_t start_bit_idx, const unsigned char *input,
		const size_t input_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert((input != NULL) | (input_bit_len == 0));

	if (start_bit_idx % 8 != 0) {
		return 1;
	}

	size_t width_bytes = p->width / 8;
	size_t si = start_bit_idx / 8;

	if (si >= width_bytes) {
		return 1;
	}

	if (width_bytes - si < (input_bit_len + 7) / 8) {
		return 1;
	}

	unsigned char *state = p->internal;
	size_t input_byte_len = input_bit_len / 8;
	size_t ii = 0;
	for (; ii < input_byte_len; si++, ii++) {
		assert(si < width_bytes);
		state[si] ^= input[ii];
	}

	/* Handle the last byte and make sure we only use the relevant bits. */
	size_t remaining_bits = input_bit_len % 8;
	if (remaining_bits != 0) {
		assert(si < width_bytes);

		unsigned char last_byte = input[ii];
		last_byte >>= 8 - remaining_bits;
		state[si] ^= last_byte;
	}

	return 0;
}

static int get(permutation *p, const size_t start_bit_idx, unsigned char *output,
		const size_t output_bit_len)
{
	assert(p != NULL);
	assert(p->internal != NULL);

	assert((output != NULL) | (output_bit_len == 0));

	if (start_bit_idx % 8 != 0) {
		return 1;
	}

	size_t width_bytes = p->width / 8;
	size_t si = start_bit_idx / 8;

	if (si >= width_bytes) {
		return 1;
	}

	if (width_bytes - si < (output_bit_len + 7) / 8) {
		return 1;
	}

	unsigned char *state = p->internal;
	size_t output_byte_len = output_bit_len / 8;

	assert(output_byte_len <= width_bytes - si);

	memcpy(output, state + si, output_byte_len);

	size_t remaining_bits = output_bit_len % 8;
	if (remaining_bits != 0) {
		assert(si + output_byte_len < width_bytes);

		unsigned char last_byte = state[si + output_byte_len];
		last_byte <<= 8 - remaining_bits;
		output[output_byte_len] = last_byte;
	}

	return 0;
}
