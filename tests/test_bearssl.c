/*
 * test_bearssl - crypt68k's BearSSL drop-ins against BearSSL's own code:
 * RSA's public operation (c68k_br_rsa_public against br_rsa_i32_public)
 * on random odd moduli of every size to 4096 bits, random exponents and
 * the edges (x >= n, even moduli, leading zeros, a wrong length, e = 0);
 * PKCS#1 signatures from keys BearSSL generates (good, broken, short);
 * ECDSA (c68k_br_ecdsa_vrfy_* against br_ecdsa_i31_*) with keys and
 * signatures BearSSL makes on P-256 and P-384 over 20- to 64-byte hashes,
 * good ones (and with s replaced by n - s) accepted, and the same answer
 * from both for other hashes, broken DER, r or s zero or n, odd lengths,
 * random r and s, and keys off the curve, short or compressed; P-521
 * goes through to BearSSL.
 *
 *   test_bearssl [rsa-cases [keys]]    (defaults 3000 and 40)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bearssl.h"
#include "crypt68k_bearssl.h"

static int fails, runs;
static uint32_t g_rng = 2463534242u;

static uint32_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 17;
	g_rng ^= g_rng << 5;
	return g_rng;
}

static void fill(unsigned char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (unsigned char)rnd();
}

/* the same answer from both, for n (nlen bytes, maybe with leading
 * zeros), e and x (xlen bytes) */
static void same(const char *what, const unsigned char *n, size_t nlen,
	const unsigned char *e, size_t elen, const unsigned char *x, size_t xlen)
{
	unsigned char a[512], b[512];
	br_rsa_public_key pk;
	uint32_t ra, rb;

	pk.n = (unsigned char *)n;
	pk.nlen = nlen;
	pk.e = (unsigned char *)e;
	pk.elen = elen;
	memcpy(a, x, xlen);
	memcpy(b, x, xlen);
	ra = c68k_br_rsa_public(a, xlen, &pk);
	rb = br_rsa_i32_public(b, xlen, &pk);
	runs++;
	if (ra != rb || (ra && memcmp(a, b, xlen) != 0)) {
		fails++;
		if (fails < 10)
			printf("FAIL %s: nlen %lu elen %lu xlen %lu: rsavrfy %lu, i32 %lu%s\n",
				what, (unsigned long)nlen, (unsigned long)elen,
				(unsigned long)xlen, (unsigned long)ra, (unsigned long)rb,
				ra == rb ? ", different answers" : "");
	}
}

/* a random odd modulus of len bytes (top byte nonzero, not 1) */
static void modulus(unsigned char *n, size_t len)
{
	fill(n, len);
	n[0] |= (unsigned char)(len == 1 ? 2 : 1);
	n[len - 1] |= 1;
}

/* a random x below n (same length): the top byte kept below n's */
static void below(unsigned char *x, const unsigned char *n, size_t len)
{
	fill(x, len);
	x[0] = (unsigned char)(n[0] > 1 ? rnd() % n[0] : 0);
	if (len == 1)
		x[0] = (unsigned char)(rnd() % n[0]);
}

static void publics(int cases)
{
	static const unsigned char e65537[3] = { 1, 0, 1 }, e3[1] = { 3 },
		e0[2] = { 0, 0 }, e1[1] = { 1 }, elead[5] = { 0, 0, 1, 0, 1 };
	unsigned char n[514], x[512], e[4];
	int i;

	for (i = 0; i < cases; i++) {
		size_t len = i < cases * 2 / 3 ? 1 + rnd() % 64
			: i < cases * 29 / 30 ? 1 + rnd() % 256 : 1 + rnd() % 512;
		size_t elen = 1 + rnd() % 4;

		modulus(n, len);
		fill(e, elen);
		below(x, n, len);
		switch (rnd() % 4) {
		case 0:
			same("random e", n, len, e, elen, x, len);
			break;
		case 1:
			same("e = 65537", n, len, e65537, 3, x, len);
			break;
		case 2:
			same("e = 3", n, len, e3, 1, x, len);
			break;
		default:
			same("e leading zeros", n, len, elead, 5, x, len);
		}
	}
	/* the sizes certificates use, e = 65537 */
	for (i = 0; i < 6; i++) {
		static const size_t sizes[] = { 128, 256, 384, 512, 255, 257 };
		size_t len = sizes[i];

		modulus(n, len);
		n[0] |= 0x80;
		below(x, n, len);
		same("certificate sizes", n, len, e65537, 3, x, len);
	}
	/* the edges */
	modulus(n, 256);
	memset(x, 0, 256);
	same("x = 0", n, 256, e65537, 3, x, 256);
	memcpy(x, n, 256);
	x[255] -= 1;
	same("x = n - 1", n, 256, e65537, 3, x, 256);
	memcpy(x, n, 256);
	same("x = n", n, 256, e65537, 3, x, 256);
	memset(x, 0xff, 256);
	same("x > n", n, 256, e65537, 3, x, 256);
	below(x, n, 256);
	same("e = 0", n, 256, e0, 2, x, 256);
	same("e = 1", n, 256, e1, 1, x, 256);
	same("xlen short", n, 256, e65537, 3, x, 255);
	n[255] &= 0xfe;
	same("even modulus", n, 256, e65537, 3, x, 256);
	/* leading zeros on n: x has the length without them */
	n[0] = n[1] = 0;
	modulus(n + 2, 254);
	below(x, n + 2, 254);
	same("n leading zeros", n, 256, e65537, 3, x, 254);
	same("n leading zeros, xlen with them", n, 256, e65537, 3, x, 256);
}

static void signatures(void)
{
	const unsigned char *oid = BR_HASH_OID_SHA256;
	static const unsigned sizes[] = { 1024, 2048, 3072, 4096 };
	static unsigned char kpriv[BR_RSA_KBUF_PRIV_SIZE(4096)];
	static unsigned char kpub[BR_RSA_KBUF_PUB_SIZE(4096)];
	br_hmac_drbg_context rng;
	br_rsa_private_key sk;
	br_rsa_public_key pk;
	unsigned char hash[32], got[32], sig[512];
	size_t i;

	br_hmac_drbg_init(&rng, &br_sha256_vtable, "test_rsa", 8);
	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		size_t len = sizes[i] / 8;
		char what[64];

		if (!br_rsa_i31_keygen(&rng.vtable, &sk, kpriv, &pk, kpub, sizes[i], 65537)) {
			printf("FAIL keygen %u\n", sizes[i]);
			fails++;
			continue;
		}
		fill(hash, sizeof hash);
		if (!br_rsa_i31_pkcs1_sign(oid, hash, sizeof hash, &sk, sig)) {
			printf("FAIL sign %u\n", sizes[i]);
			fails++;
			continue;
		}
		runs++;
		snprintf(what, sizeof what, "RSA-%u signature", sizes[i]);
		memset(got, 0, sizeof got);
		if (!c68k_br_rsa_pkcs1_vrfy(sig, len, oid, sizeof hash, &pk, got)
			|| memcmp(got, hash, sizeof hash) != 0) {
			printf("FAIL %s: refused, or a different hash\n", what);
			fails++;
		}
		runs++;
		sig[len / 2] ^= 0x10;
		if (c68k_br_rsa_pkcs1_vrfy(sig, len, oid, sizeof hash, &pk, got)) {
			printf("FAIL %s: a broken one accepted\n", what);
			fails++;
		}
		sig[len / 2] ^= 0x10;
		runs++;
		if (c68k_br_rsa_pkcs1_vrfy(sig, len - 1, oid, sizeof hash, &pk, got)) {
			printf("FAIL %s: a short one accepted\n", what);
			fails++;
		}
	}
}


/* --- ECDSA ---------------------------------------------------------------- */

/* both must say want (-1: both the same, whatever it is) */
static void both(const char *what, int want, const void *hash, size_t hlen,
	const br_ec_public_key *pk, const void *sig, size_t slen, int raw)
{
	uint32_t a, b;

	if (raw) {
		a = c68k_br_ecdsa_vrfy_raw(&br_ec_all_m31, hash, hlen, pk, sig, slen);
		b = br_ecdsa_i31_vrfy_raw(&br_ec_all_m31, hash, hlen, pk, sig, slen);
	} else {
		a = c68k_br_ecdsa_vrfy_asn1(&br_ec_all_m31, hash, hlen, pk, sig, slen);
		b = br_ecdsa_i31_vrfy_asn1(&br_ec_all_m31, hash, hlen, pk, sig, slen);
	}
	runs++;
	if (a != b || (want >= 0 && a != (uint32_t)want)) {
		fails++;
		if (fails < 12)
			printf("FAIL %s (curve %d, hash %lu): ecvrfy %lu, i31 %lu, want %d\n",
				what, pk->curve, (unsigned long)hlen, (unsigned long)a,
				(unsigned long)b, want);
	}
}

/* big-endian x = n - x (len bytes) */
static void negate(unsigned char *x, const unsigned char *n, size_t len)
{
	int bw = 0;
	size_t i;

	for (i = len; i-- > 0;) {
		int d = n[i] - x[i] - bw;

		bw = d < 0;
		x[i] = (unsigned char)(d & 0xff);
	}
}

static const unsigned char *order(int curve, size_t *len)
{
	/* the orders (FIPS 186-4) */
	static const unsigned char n256[32] = {
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
		0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
	static const unsigned char n384[48] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
		0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73 };

	*len = curve == BR_EC_secp256r1 ? 32 : 48;
	return curve == BR_EC_secp256r1 ? n256 : n384;
}

static void one_key(br_hmac_drbg_context *rng, int curve)
{
	static const br_hash_class *const hashes[] = {
		&br_sha1_vtable, &br_sha256_vtable, &br_sha384_vtable, &br_sha512_vtable };
	unsigned char kpriv[BR_EC_KBUF_PRIV_MAX_SIZE], kpub[BR_EC_KBUF_PUB_MAX_SIZE];
	unsigned char hash[64], sig[160], raw[160], q[BR_EC_KBUF_PUB_MAX_SIZE];
	br_ec_private_key sk;
	br_ec_public_key pk, bad;
	const br_hash_class *hf = hashes[rnd() % 4];
	size_t hlen = (hf->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
	size_t slen, rlen, nlen, i;
	const unsigned char *n = order(curve, &nlen);

	if (!br_ec_keygen(&rng->vtable, &br_ec_all_m31, &sk, kpriv, curve)
		|| !br_ec_compute_pub(&br_ec_all_m31, &pk, kpub, &sk)) {
		printf("FAIL keygen on curve %d\n", curve);
		fails++;
		return;
	}
	fill(hash, hlen);
	slen = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, hf, hash, &sk, sig);
	if (slen == 0) {
		printf("FAIL sign on curve %d\n", curve);
		fails++;
		return;
	}
	both("good", 1, hash, hlen, &pk, sig, slen, 0);
	memcpy(raw, sig, slen);
	rlen = br_ecdsa_asn1_to_raw(raw, slen);
	both("good, raw", 1, hash, hlen, &pk, raw, rlen, 1);

	/* s -> n - s: as good */
	negate(raw + rlen / 2, n, nlen);
	both("n - s", 1, hash, hlen, &pk, raw, rlen, 1);
	negate(raw + rlen / 2, n, nlen);

	/* another hash (in the bytes used: those to the order's length), a
	 * broken signature */
	hash[rnd() % (hlen < nlen ? hlen : nlen)] ^= (unsigned char)(1 << rnd() % 8);
	both("other hash", 0, hash, hlen, &pk, raw, rlen, 1);
	for (i = 0; i < 3; i++) {
		unsigned char b[160];
		size_t at = rnd() % slen;

		memcpy(b, sig, slen);
		b[at] ^= (unsigned char)(1 << rnd() % 8);
		both("broken ASN.1", -1, hash, hlen, &pk, b, slen, 0);
	}

	/* r, s = 0 or n; odd length; random */
	{
		unsigned char b[160];
		size_t h = rlen / 2;

		memcpy(b, raw, rlen);
		memset(b, 0, h);
		both("r = 0", 0, hash, hlen, &pk, b, rlen, 1);
		memcpy(b, raw, rlen);
		memset(b + h, 0, h);
		both("s = 0", 0, hash, hlen, &pk, b, rlen, 1);
		if (h == nlen) {
			memcpy(b, raw, rlen);
			memcpy(b, n, nlen);
			both("r = n", 0, hash, hlen, &pk, b, rlen, 1);
			memcpy(b, raw, rlen);
			memcpy(b + h, n, nlen);
			both("s = n", 0, hash, hlen, &pk, b, rlen, 1);
		}
		both("odd length", 0, hash, hlen, &pk, raw, rlen - 1, 1);
		fill(b, rlen);
		b[0] &= 0x7f;
		b[h] &= 0x7f;
		both("random r, s", 0, hash, hlen, &pk, b, rlen, 1);
	}

	/* the key off the curve, the wrong length, compressed */
	memcpy(q, pk.q, pk.qlen);
	bad = pk;
	bad.q = q;
	q[pk.qlen - 1] ^= 1;
	both("Q off the curve", 0, hash, hlen, &bad, raw, rlen, 1);
	q[pk.qlen - 1] ^= 1;
	bad.qlen = pk.qlen - 1;
	both("Q short", 0, hash, hlen, &bad, raw, rlen, 1);
	bad.qlen = pk.qlen;
	q[0] = 0x02;
	both("Q compressed", 0, hash, hlen, &bad, raw, rlen, 1);
}


int main(int argc, char **argv)
{
	int keys = argc > 2 ? atoi(argv[2]) : 40, i;
	br_hmac_drbg_context rng;

	publics(argc > 1 ? atoi(argv[1]) : 3000);
	signatures();
	br_hmac_drbg_init(&rng, &br_sha256_vtable, "test_ecdsa", 10);
	for (i = 0; i < keys; i++) {
		one_key(&rng, BR_EC_secp256r1);
		one_key(&rng, BR_EC_secp384r1);
	}
	/* P-521: to BearSSL */
	{
		unsigned char kpriv[BR_EC_KBUF_PRIV_MAX_SIZE], kpub[BR_EC_KBUF_PUB_MAX_SIZE];
		unsigned char hash[64], sig[160];
		br_ec_private_key sk;
		br_ec_public_key pk;
		size_t slen;

		br_ec_keygen(&rng.vtable, &br_ec_all_m31, &sk, kpriv, BR_EC_secp521r1);
		br_ec_compute_pub(&br_ec_all_m31, &pk, kpub, &sk);
		fill(hash, 64);
		slen = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, &br_sha512_vtable, hash, &sk, sig);
		both("P-521 good", 1, hash, 64, &pk, sig, slen, 0);
		hash[5] ^= 1;
		both("P-521 other hash", 0, hash, 64, &pk, sig, slen, 0);
	}
	printf("crypt68k against BearSSL: %d/%d passed\n", runs - fails, runs);
	return fails ? 1 : 0;
}
