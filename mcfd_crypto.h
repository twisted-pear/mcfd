#ifndef __MCFD_CRYPTO_H__
#define __MCFD_CRYPTO_H__

#define MCFD_BLOCK_SIZE 128
#define MCFD_KEY_BITS 256
/* FIXME: Probably not long enough. */
#define MCFD_NONCE_BITS 64
#define MCFD_TAG_BITS 512

#include <stdint.h>

typedef struct mcfd_cipher_t mcfd_cipher;

mcfd_cipher *mcfd_cipher_init(const unsigned char *init_nonce, const unsigned char *key);
void mcfd_cipher_free(mcfd_cipher *cipher);

int mcfd_cipher_encrypt(mcfd_cipher *cipher, const unsigned char *plaintext,
		const size_t plaintext_bytes, unsigned char *ciphertext,
		unsigned char *tag);
int mcfd_cipher_decrypt(mcfd_cipher *cipher, const unsigned char *ciphertext,
		const size_t ciphertext_bytes, const unsigned char *tag,
		unsigned char *plaintext);

#endif /* __MCFD_CRYPTO_H__ */
