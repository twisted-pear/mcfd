#ifndef __MCFD_KDF_H__
#define __MCFD_KDF_H__

#define MCFD_SALT_BITS 128
#define MCFD_SALT_BYTES (MCFD_SALT_BITS / 8)

#define MCFD_KDF_DEF_ITERATIONS 10000

#include <stdint.h>

int mcfd_kdf(const char *pass, const size_t pass_len, const unsigned char *salt,
		const size_t iterations, unsigned char *key, const size_t key_bits);

#endif /* __MCFD_KDF_H__ */
