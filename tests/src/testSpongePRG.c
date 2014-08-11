#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>
#include "spongeprg.h"

#define DEF_SEED (unsigned char *) "asdfasdf"

int testSpongePRG(void)
{
	/* TODO */

	return 0;
}

int main(void)
{
	return testSpongePRG();
}
