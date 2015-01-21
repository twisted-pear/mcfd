#ifndef __MCFD_CRYPTO_H__
#define __MCFD_CRYPTO_H__

#define MCFD_BLOCK_SIZE 1024

#define MCFD_KEY_BITS 256
#define MCFD_KEY_BYTES (MCFD_KEY_BITS / 8)

#define MCFD_NONCE_BITS 256
#define MCFD_NONCE_BYTES (MCFD_NONCE_BITS / 8)

#define MCFD_TAG_BITS 256
#define MCFD_TAG_BYTES (MCFD_TAG_BITS / 8)

#define MCFD_SALT_BITS 128
#define MCFD_SALT_BYTES (MCFD_SALT_BYTES / 8)

#define MCFD_KDF_DEF_ITERATIONS 10000

#include <stdint.h>

int mcfd_kdf(const char *pass, const size_t pass_len, const unsigned char *salt,
		const size_t iterations, unsigned char *key);

typedef struct mcfd_cipher_t mcfd_cipher;

mcfd_cipher *mcfd_cipher_init(const unsigned char *init_nonce, const unsigned char *key);
void mcfd_cipher_free(mcfd_cipher *cipher);

int mcfd_cipher_set_nonce(mcfd_cipher *cipher, const unsigned char *nonce);

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag);
int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext);

#endif /* __MCFD_CRYPTO_H__ */
