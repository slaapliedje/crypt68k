/*
 * bench - how long crypt68k takes on this machine: X25519, RSA-2048 and
 * RSA-4096's public operation, ECDSA on P-256 and P-384, each repeated
 * for at least two seconds of CPU time (clock()). Integers only: some
 * 68k C libraries have no floating point.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "crypt68k.h"
#include "vectors.h"

static long ms(clock_t d)
{
	long t = (long)d, cps = (long)CLOCKS_PER_SEC;

	return t / cps * 1000 + t % cps * 1000 / cps;
}

static const struct rsavec *rsa_of(size_t len)
{
	size_t i;

	for (i = 0; i < sizeof rsavecs / sizeof rsavecs[0]; i++)
		if (rsavecs[i].len == len && rsavecs[i].elen == 3)
			return &rsavecs[i];
	return NULL;
}

static const struct ecvec *ec_of(int curve)
{
	size_t i;

	for (i = 0; i < sizeof ecvecs / sizeof ecvecs[0]; i++)
		if (ecvecs[i].curve == curve && ecvecs[i].want == 1)
			return &ecvecs[i];
	return NULL;
}

static void time_rsa(size_t len)
{
	const struct rsavec *v = rsa_of(len);
	unsigned char x[512];
	clock_t t0 = clock();
	long n = 0, t;

	if (v == NULL)
		return;
	do {
		memcpy(x, v->x, len);
		c68k_rsa_public(x, len, v->n, len, v->e, v->elen);
		n++;
	} while ((t = ms(clock() - t0)) < 2000);
	printf("  RSA-%-4lu public op   %6ld ms\n", (unsigned long)len * 8, t / n);
}

static void time_ec(int curve, const char *name)
{
	const struct ecvec *v = ec_of(curve);
	size_t len = c68k_ec_len(curve);
	clock_t t0 = clock();
	long n = 0, t;

	if (v == NULL)
		return;
	do {
		c68k_ecdsa_verify_raw(curve, v->q, 1 + 2 * len, v->h, v->hlen, v->raw, 2 * len);
		n++;
	} while ((t = ms(clock() - t0)) < 2000);
	printf("  ECDSA %s verify   %6ld ms\n", name, t / n);
}

static void time_x25519(void)
{
	unsigned char out[32];
	clock_t t0 = clock();
	long n = 0, t;

	do {
		c68k_x25519(out, xvecs[0].k, xvecs[0].u);
		n++;
	} while ((t = ms(clock() - t0)) < 2000);
	printf("  X25519                 %6ld ms\n", t / n);
}

int main(void)
{
	printf("crypt68k, an operation at a time:\n");
	time_x25519();
	time_rsa(256);
	time_rsa(512);
	time_ec(C68K_P256, "P-256");
	time_ec(C68K_P384, "P-384");
	return 0;
}
