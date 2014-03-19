#ifndef __PAD_H__
#define __PAD_H__

#include <stdint.h>

typedef struct pad_t {
	size_t rate;
	size_t min_bit_len;
	int (*pf)(struct pad_t *, unsigned char *, const size_t);
	void *internal;
} pad;

#endif /* __PAD_H__ */
