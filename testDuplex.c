/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakF-1600.h"
#include "KeccakPad_10_1.h"
#include "duplex.h"

void testDuplexOneInstance(FILE *f, unsigned int rate, unsigned int capacity)
{
    permutation *pf = keccakF_1600_init();
    pad *p = keccakPad_10_1_init(rate);
    duplex *duplex = duplex_init(pf, p, rate);

    unsigned char acc[pf->width/8];
    unsigned char sigma[pf->width/8];
    unsigned char Z[pf->width/8];
    unsigned int sigmaBitLength, ZByteLen, i;
    //Keccak_DuplexInstance duplex;

    // Acumulated test vector
    memset(acc, 0x00, sizeof(acc));
    
    //Keccak_DuplexInitialize(&duplex, rate, capacity);
    
    // Varying input size, maximum output size
    for(sigmaBitLength=0; sigmaBitLength<=rate-2; sigmaBitLength++) {
        unsigned int sigmaByteLenCeiling = (sigmaBitLength + 7)/8;
        unsigned int ZByteLen = (rate + 7)/8;
        //unsigned char delimitedSigmaEnd;
        unsigned char filler = 0xAA + sigmaBitLength;

        for(i=0; i<sigmaByteLenCeiling; i++)
            sigma[i] = (unsigned char)(sigmaBitLength - i);
        if ((sigmaBitLength % 8) != 0) {
            //sigma[sigmaByteLenCeiling-1] &= (1 << (sigmaBitLength % 8)) - 1;
            //delimitedSigmaEnd = sigma[sigmaByteLenCeiling-1] | (1 << (sigmaBitLength % 8));
            sigma[sigmaByteLenCeiling-1] <<= (8 - (sigmaBitLength % 8));
        }
        //else
            //delimitedSigmaEnd = 0x01;

        memset(Z, filler, sizeof(Z));
	size_t out_bit_len = (ZByteLen * 8 > rate) ? rate : ZByteLen * 8;
	duplex_duplexing(duplex, sigma, sigmaBitLength, Z, out_bit_len);
	if (ZByteLen * 8 > rate) {
		Z[ZByteLen - 1] >>= 8 - (out_bit_len % 8);
	}
        //Keccak_Duplexing(&duplex, sigma, sigmaBitLength/8, Z, ZByteLen, delimitedSigmaEnd);

        for(i=0; i<ZByteLen; i++)
            acc[i] ^= Z[i];
        for(i=ZByteLen; i<sizeof(Z); i++)
            if (Z[i] != filler) {
                printf("Out of range data written!\n");
                abort();
            }
    }
    
    // No input, varying output size
    for(ZByteLen=0; ZByteLen<=(rate+7)/8; ZByteLen++) {
        unsigned char filler = 0x33 + sigmaBitLength;

        memset(Z, filler, sizeof(Z));
	size_t out_bit_len = (ZByteLen * 8 > rate) ? rate : ZByteLen * 8;
	duplex_duplexing(duplex, 0, 0, Z, out_bit_len);
	if (ZByteLen * 8 > rate) {
		Z[ZByteLen - 1] >>= 8 - (out_bit_len % 8);
	}
        //Keccak_Duplexing(&duplex, 0, 0, Z, ZByteLen, 0x01);

        for(i=0; i<ZByteLen; i++)
            acc[i] ^= Z[i];
        for(i=ZByteLen; i<sizeof(Z); i++)
            if (Z[i] != filler) {
                printf("Out of range data written!\n");
                abort();
            }
    }
    
    fprintf(f, "Keccak[r=%d, c=%d] duplex: ", rate, capacity);
    for(i=0; i<(rate+7)/8; i++)
        fprintf(f, "%02x ", acc[i]);
    fprintf(f, "\n\n");

    keccakF_1600_free(pf);
    keccakPad_10_1_free(p);
    duplex_free(duplex);
}

void testDuplex()
{
    FILE *f;
    unsigned int rate;
    
    f = fopen("TestDuplex.txt", "w");
    for(rate = 3; rate <= 1600-2; rate += (rate < 68) ? 1 : ((rate < 220) ? 5 : 25))
        testDuplexOneInstance(f, rate, 1600-rate);
    fclose(f);
}
