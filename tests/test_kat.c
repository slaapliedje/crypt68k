/*
 * test_kat - crypt68k against known answers (vectors.h, made by
 * gen_vectors.py with Python's integers): RSA's public operation on
 * moduli of 512 to 4096 bits, and ECDSA signatures on P-256 and P-384
 * through the raw and DER calls and the steps, with ones that must fail;
 * X25519 against RFC 7748's answers and more (u = 0, 1, p, above p, the
 * top bit set), and iterated once (test_kat long: a thousand times, as
 * the RFC does; minutes on a 68030). Needs nothing but the library: build
 * it for the 68k machine and run it there.
 */
#include <stdio.h>
#include <string.h>
#include "crypt68k.h"
#include "vectors.h"

static int fails, runs;

static void check(const char *what, int ok)
{
	runs++;
	if (!ok) {
		fails++;
		printf("FAIL %s\n", what);
	}
}

int main(int argc, char **argv)
{
	static unsigned char x[512];
	char what[96];
	size_t i;

	for (i = 0; i < sizeof rsavecs / sizeof rsavecs[0]; i++) {
		const struct rsavec *v = &rsavecs[i];

		memcpy(x, v->x, v->len);
		sprintf(what, "RSA-%lu, e of %lu byte(s)", (unsigned long)v->len * 8,
			(unsigned long)v->elen);
		check(what, c68k_rsa_public(x, v->len, v->n, v->len, v->e, v->elen) == 1
			&& memcmp(x, v->y, v->len) == 0);
		/* x = n: refused */
		memcpy(x, v->n, v->len);
		sprintf(what, "RSA-%lu, x = n refused", (unsigned long)v->len * 8);
		check(what, c68k_rsa_public(x, v->len, v->n, v->len, v->e, v->elen) == 0);
	}
	for (i = 0; i < sizeof ecvecs / sizeof ecvecs[0]; i++) {
		const struct ecvec *v = &ecvecs[i];
		size_t len = c68k_ec_len(v->curve), qlen = 1 + 2 * len;
		unsigned char u1[48], u2[48], xx[48];
		int steps;

		sprintf(what, "%s, raw", v->what);
		check(what, c68k_ecdsa_verify_raw(v->curve, v->q, qlen, v->h, v->hlen,
			v->raw, 2 * len) == v->want);
		sprintf(what, "%s, DER", v->what);
		check(what, c68k_ecdsa_verify_asn1(v->curve, v->q, qlen, v->h, v->hlen,
			v->der, v->derlen) == v->want);
		steps = c68k_ec_point(v->curve, v->q, qlen)
			&& c68k_ecdsa_scalars(v->curve, u1, u2, v->raw, v->raw + len, len, v->h, v->hlen)
			&& c68k_ec_muladd(v->curve, xx, v->q, u1, u2)
			&& c68k_ec_x_is_r(v->curve, xx, v->raw, len);
		sprintf(what, "%s, in steps", v->what);
		check(what, steps == v->want);
	}
	/* malformed DER and other lengths */
	{
		const struct ecvec *v = &ecvecs[0];
		unsigned char d[160];

		memcpy(d, v->der, v->derlen);
		d[v->derlen] = 0;
		check("DER with a byte after it", c68k_ecdsa_verify_asn1(v->curve, v->q, 65,
			v->h, v->hlen, d, v->derlen + 1) == 0);
		check("DER cut short", c68k_ecdsa_verify_asn1(v->curve, v->q, 65,
			v->h, v->hlen, v->der, v->derlen - 1) == 0);
		check("raw of odd length", c68k_ecdsa_verify_raw(v->curve, v->q, 65,
			v->h, v->hlen, v->raw, 63) == 0);
		check("an unknown curve", c68k_ecdsa_verify_raw(25, v->q, 65,
			v->h, v->hlen, v->raw, 64) == 0);
		check("Q of the wrong length", c68k_ecdsa_verify_raw(v->curve, v->q, 64,
			v->h, v->hlen, v->raw, 64) == 0);
	}
	/* X25519 */
	for (i = 0; i < sizeof xvecs / sizeof xvecs[0]; i++) {
		unsigned char out[32];

		c68k_x25519(out, xvecs[i].k, xvecs[i].u);
		sprintf(what, "X25519 %s", xvecs[i].what);
		check(what, memcmp(out, xvecs[i].out, 32) == 0);
	}
	{
		unsigned char k[32], u[32], t[32];
		int n, iters = argc > 1 && strcmp(argv[1], "long") == 0 ? 1000 : 1;

		memset(k, 0, 32);
		k[0] = 9;
		memcpy(u, k, 32);
		for (n = 0; n < iters; n++) {
			c68k_x25519(t, k, u);
			memcpy(u, k, 32);
			memcpy(k, t, 32);
		}
		check(iters == 1 ? "X25519 iterated once" : "X25519 iterated 1000 times",
			memcmp(k, iters == 1 ? x_iter1 : x_iter1000, 32) == 0);
		c68k_x25519_base(t, xvecs[2].k);
		check("X25519 base point", memcmp(t, xvecs[2].out, 32) == 0);
	}
	printf("crypt68k: %d/%d known answers right\n", runs - fails, runs);
	return fails ? 1 : 0;
}
