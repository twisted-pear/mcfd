#ifndef __PERMUTATION_H__
#define __PERMUTATION_H__

#include <stdint.h>

typedef struct permutation_t {
	size_t width;
	int (*f)(struct permutation_t *);
	int (*xor)(struct permutation_t *, const size_t, const unsigned char *,
			const size_t);
	int (*get)(struct permutation_t *, const size_t, unsigned char *, const size_t);
	void *internal;
} permutation;

#endif /* __PERMUTATION_H__ */
