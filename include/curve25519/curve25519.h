#ifndef __CURVE25519_H__
#define __CURVE25519_H__

#define CURVE25519_PRIVATE_BYTES 32
#define CURVE25519_PUBLIC_BYTES 32
#define CURVE25519_SHARED_BYTES 32

void curve25519_clamp(unsigned char *privkey);
void curve25519_public(const unsigned char *privkey, unsigned char *pubkey);
void curve25519(unsigned char *shared, const unsigned char *my_privkey,
		const unsigned char *their_pubkey);

#endif /* __CURVE25519_H__ */
