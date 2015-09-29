#ifndef __MCFD_RANDOM_H__
#define __MCFD_RANDOM_H__

#include <stdint.h>

/* The maximum number of random bytes the application can request with a single call to
 * mcfd_random_get().
 * This limit is imposed by the getrandom() syscall which is more complicated to use if
 * more than 256 bytes are requested. */
#define MCFD_RANDOM_REQUEST_MAX 256

int mcfd_random_init(void);
void mcfd_random_destroy(void);

int mcfd_random_reseed(void);

int mcfd_random_get(unsigned char *outbuf, const size_t outbuf_size);

#endif /* __MCFD_RANDOM_H__ */
