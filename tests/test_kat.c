/*
 * test_kat - crypt68k against known answers (vectors.h, made by
 * gen_vectors.py with Python's integers): RSA's public operation on
 * moduli of 512 to 4096 bits, and ECDSA signatures on P-256 and P-384
 * through the raw and DER calls and the steps, with ones that must fail.
 * Needs nothing but the library: build it for the 68k machine and run
 * it there.
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

int main(void)
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
	printf("crypt68k: %d/%d known answers right\n", runs - fails, runs);
	return fails ? 1 : 0;
}
