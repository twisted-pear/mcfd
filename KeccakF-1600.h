#ifndef __KECCAKF_1600_H__
#define __KECCAKF_1600_H__

#include "permutation.h"

permutation *keccakF_1600_init(void);
void keccakF_1600_free(permutation *p);

#endif /* __KECCAKF_1600_H__ */
