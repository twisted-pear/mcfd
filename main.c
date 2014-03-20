#include <stdio.h>
#include <string.h>

#include "sponge.h"

#include "KeccakPad_10_1.h"
#include "KeccakF-1600.h"

extern int genKAT_main(void);
extern void testDuplex(void);

int main(void)
{
	/* TODO: test for mem leaks */
	testDuplex();
	return genKAT_main();
}
