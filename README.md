# crypt68k

Fast signature checks for 68k machines: RSA's public operation, and
ECDSA on P-256 and P-384. They're what a TLS client spends its first
visit to a site on: checking the certificate chain and the server's key
exchange. Plain C89 with one hand-written 68020/030/040 loop, MIT
licensed, and a drop-in for [BearSSL](https://bearssl.org).

On a 32 MHz 68030 (an Atari TT030), against BearSSL 0.6's fastest code
for each:

| | BearSSL | crypt68k |
|---|---|---|
| RSA-2048 public operation | 2.30 s (`i32`) | 0.62 s |
| RSA-4096 public operation | 9.61 s (`i32`) | 2.30 s |
| ECDSA P-256 check | 5.49 s (`p256_m31`) | 1.89 s |
| ECDSA P-384 check | 42.2 s (`prime_i31`) | 5.59 s |

(crypt68k's `bench`; BearSSL's own `tlsbench` figures from Manx, the
same machine.)

In [Manx](https://github.com/slaapliedje/manx), the browser it comes
from, a TT's first visit to a site with a Let's Encrypt P-384 chain went
from 147 s to 27 s.

## Only for public data

**Everything here takes a time that depends on its inputs.** That is
what makes it fast, and it is fine for checking signatures: the
signature, the public key and the hash are all public. It is not fine
for anything secret. Never use crypt68k to sign, to decrypt, to encrypt
a secret with RSA (RSA key exchange), or for a key exchange of any kind.

## Why it's faster

- **Montgomery multiplication on 32-bit limbs** (CIOS), its inner loop
  eight 68k instructions around `mulu.l`'s 32x32 -> 64 multiply.
- **RSA for public exponents:** left-to-right square-and-multiply, 18
  multiplications for e = 65537. BearSSL's general modpow, built to keep
  a private exponent secret, does two for every bit of the exponent's
  bytes: 48.
- **ECDSA:** Jacobian coordinates (a = -3), u1 G + u2 Q by interleaved
  width-4 NAF over affine tables of G, 3G, 5G, 7G (made once) and the
  same for Q, inverses by binary GCD. All of it variable time, which a
  check can afford.

## Using it

```c
#include "crypt68k.h"

/* RSA: x = x^e mod n (then check the PKCS#1 padding against the hash) */
ok = c68k_rsa_public(x, xlen, n, nlen, e, elen);

/* ECDSA: q uncompressed (0x04, x, y); sig raw (r, s) or DER */
ok = c68k_ecdsa_verify_asn1(C68K_P384, q, qlen, hash, hash_len, sig, sig_len);
```

`crypt68k.h` also has the ECDSA check in steps (`c68k_ecdsa_scalars`,
`c68k_ec_muladd`, `c68k_ec_x_is_r`), for doing the heavy step somewhere
else: Manx hands it to the transputer on an ATW800/2 card.

### With BearSSL

`crypt68k_bearssl.h` has BearSSL's signature checker types. In a client's
setup:

```c
br_ssl_engine_set_rsavrfy(&cc.eng, c68k_br_rsa_pkcs1_vrfy);
br_ssl_engine_set_ecdsa(&cc.eng, c68k_br_ecdsa_vrfy_asn1);
br_x509_minimal_set_rsa(&xc, c68k_br_rsa_pkcs1_vrfy);
br_x509_minimal_set_ecdsa(&xc, &br_ec_all_m31, c68k_br_ecdsa_vrfy_asn1);
```

Not `br_ssl_engine_set_rsapub`: that one encrypts the premaster secret in
RSA key exchange suites. Curves other than P-256 and P-384 go on to
BearSSL's `br_ecdsa_i31`.

## Building

```sh
make                 # libcrypt68k.a, test_kat, bench (here)
make test            # the known answers
make BEARSSL=../BearSSL test    # also the drop-ins, against BearSSL itself
```

For a 68k machine, name its compiler and CPU, then run `test_kat` and
`bench` there:

```sh
make CC=m68k-atari-mint-gcc AR=m68k-atari-mint-ar CFLAGS="-O2 -m68030"
make CC=m68k-amigaos-gcc AR=m68k-amigaos-ar CFLAGS="-O2 -m68030 -noixemul"
```

`-m68020`, `-m68030` and `-m68040` get the `mulu.l` loop. A 68060 traps
the 64-bit `mulu.l`, so `-m68060` and `-m68020-60` builds use the C loop
(`uint64_t`), as does every other machine. The 68000's multiply is
16x16 -> 32, so it is slow there either way.

## Tests

- `test_kat` checks known answers made by `tests/gen_vectors.py` with
  Python's integers: RSA on moduli of 512 to 4096 bits, and real ECDSA
  signatures on both curves over 20- to 64-byte hashes, through the raw,
  DER and step-by-step calls, with ones that must fail (another hash,
  r + 1, s = 0, r = n, a key off the curve, malformed DER). It needs
  nothing else, so it runs on the 68k machine itself.
- `test_bearssl` compares the drop-ins with BearSSL's own code: thousands
  of random RSA cases with the edges (x >= n, even moduli, leading zeros,
  wrong lengths, e = 0), PKCS#1 signatures from keys BearSSL generates,
  and ECDSA keys and signatures BearSSL makes, broken every way that
  matters, with the same answer from both.

## Licence

MIT: see `LICENSE`.
