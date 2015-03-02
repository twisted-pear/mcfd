#ifndef __MCFD_RANDOM_H__
#define __MCFD_RANDOM_H__

#include <stdint.h>

/* TODO: remove this limit */
/* The maximum number of random bytes the application can request. */
#define MCFD_RANDOM_MAX 192

int mcfd_random_init(void);
void mcfd_random_destroy(void);

int mcfd_random_reseed(void);

int mcfd_random_get(unsigned char *outbuf, const size_t outbuf_size);

#endif /* __MCFD_RANDOM_H__ */
