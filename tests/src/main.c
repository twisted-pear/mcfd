#include <stdio.h>
#include <string.h>

#include "sponge.h"

#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>

extern int genKAT_main(void);
extern void testDuplex(void);
extern int testSpongeWrap(void);
extern int testSpongePRG(void);

int main(void)
{
	/* TODO: test for mem leaks */
	testDuplex();

	if (testSpongeWrap() != 0) {
		return 1;
	}

	if (testSpongePRG() != 0) {
		return 1;
	}

	return genKAT_main();
}
