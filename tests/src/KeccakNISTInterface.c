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

#include <string.h>
#include "KeccakNISTInterface.h"

#include "sponge.h"
#include <keccak/KeccakF-1600.h>
#include <keccak/KeccakPad_10_1.h>

HashReturn Init(hashState *state, int hashbitlen)
{
    sponge *sp;
    pad *p;

    switch(hashbitlen) {
        case 0: // Default parameters, arbitrary length output
            p = keccakPad_10_1_init(1024);
            break;
        case 224:
            p = keccakPad_10_1_init(1152);
            break;
        case 256:
            p = keccakPad_10_1_init(1088);
            break;
        case 384:
            p = keccakPad_10_1_init(832);
            break;
        case 512:
            p = keccakPad_10_1_init(576);
            break;
        default:
            return BAD_HASHLEN;
    }

    if (p == NULL) {
        return FAIL;
    }

    permutation *f = keccakF_1600_init(p->rate);
    if (f == NULL) {
        goto fail_permutation;
    }

    sp = sponge_init(f, p, p->rate);
    if (sp == NULL) {
        goto fail_sponge;
    }

    state->sp = sp;
    state->outputLength = hashbitlen;

    return SUCCESS;

fail_sponge:
    keccakF_1600_free(f);
fail_permutation:
    keccakPad_10_1_free(p);

    return FAIL;
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
    return sponge_absorb(state->sp, data, databitlen);
}

HashReturn Final(hashState *state, BitSequence *hashval)
{
    HashReturn ret = sponge_absorb_final(state->sp);
    if (ret != SUCCESS) {
        goto end;
    }

    ret = sponge_squeeze(state->sp, hashval, state->outputLength);

end:
    keccakF_1600_free(state->sp->f);
    keccakPad_10_1_free(state->sp->p);
    sponge_free(state->sp);
    
    return ret;
}

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
    hashState state;
    HashReturn result;

    if ((hashbitlen != 224) && (hashbitlen != 256) && (hashbitlen != 384) && (hashbitlen != 512))
        return BAD_HASHLEN; // Only the four fixed output lengths available through this API
    result = Init(&state, hashbitlen);
    if (result != SUCCESS)
        return result;
    result = Update(&state, data, databitlen);
    if (result != SUCCESS)
        return result;
    result = Final(&state, hashval);
    return result;
}

