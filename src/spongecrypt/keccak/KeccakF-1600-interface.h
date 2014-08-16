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

#ifndef _KeccakPermutationInterface_h_
#define _KeccakPermutationInterface_h_

void KeccakInitialize( void );
void KeccakInitializeState(unsigned char *state);
void KeccakPermutation(unsigned char *state);
void KeccakAbsorb576bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb832bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb1024bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb1088bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb1152bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb1344bits(unsigned char *state, const unsigned char *data);
void KeccakAbsorb(unsigned char *state, const unsigned char *data, unsigned int laneCount);
void KeccakExtract1024bits(const unsigned char *state, unsigned char *data);
void KeccakExtract(const unsigned char *state, unsigned char *data, unsigned int laneCount);

#endif
