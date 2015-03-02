#include "curve25519.h"

extern void curve25519_donna(unsigned char *output, const unsigned char *a,
		const unsigned char *b);

void curve25519_clamp(unsigned char *privkey)
{
	privkey[0]  &= 248;
	privkey[31] &= 127;
	privkey[31] |= 64;
}

void curve25519_public(const unsigned char *privkey, unsigned char *pubkey)
{
	static const unsigned char basepoint[32] = {9};

	curve25519_donna(pubkey, privkey, basepoint);
}

void curve25519(unsigned char *shared, const unsigned char *my_privkey,
		const unsigned char *their_pubkey)
{
	curve25519_donna(shared, my_privkey, their_pubkey);
}
