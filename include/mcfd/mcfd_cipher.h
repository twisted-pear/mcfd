#ifndef __MCFD_CIPHER_H__
#define __MCFD_CIPHER_H__

#define MCFD_BLOCK_SIZE 1016

#define MCFD_KEY_BITS 256
#define MCFD_KEY_BYTES (MCFD_KEY_BITS / 8)

#define MCFD_NONCE_BITS 256
#define MCFD_NONCE_BYTES (MCFD_NONCE_BITS / 8)

#define MCFD_TAG_BITS 512
#define MCFD_TAG_BYTES (MCFD_TAG_BITS / 8)

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

#endif /* __MCFD_CIPHER_H__ */
