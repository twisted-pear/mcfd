#ifndef __KECCAKPAD_10_1_H__
#define __KECCAKPAD_10_1_H__

#include "pad.h"

#define KECCAKPAD_10_1_MIN_BIT_LEN 2

pad *keccakPad_10_1_init(const size_t rate);
void keccakPad_10_1_free(pad *p);

#endif /* __KECCAKPAD_10_1_H__ */
