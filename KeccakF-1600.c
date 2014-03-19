#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakF-1600.h"

#define L 6
#define W 64 /* 2^L */
#define NUM_ROUNDS (12 + 2 * L) /* 24 */
#define RC_WIDTH (5)
#define NUM_LANES (RC_WIDTH * RC_WIDTH) /* 25 */
#define PERMUTATION_WIDTH (NUM_LANES * W) /* 1600 */

#define IDX(X,Y) ((RC_WIDTH * ((Y) % RC_WIDTH)) + ((X) % RC_WIDTH))

static void f(permutation *p, unsigned char *state);

permutation *keccakF_1600_init(void)
{
	permutation *p = malloc(sizeof(permutation));
	if (p == NULL) {
		return NULL;
	}

	p->width = PERMUTATION_WIDTH;
	p->f = f;
	p->internal = NULL;

	return p;
}

void keccakF_1600_free(permutation *p)
{
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

static void f(permutation *p, unsigned char *state)
{
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
