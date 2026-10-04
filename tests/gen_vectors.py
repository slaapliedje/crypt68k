#!/usr/bin/env python3
# gen_vectors.py - writes tests/vectors.h: known answers for test_kat.c
# and bench.c, made with Python's integers alone (deterministic: a fixed
# seed). RSA's public operation on odd moduli of several sizes; ECDSA
# keys and signatures on P-256 and P-384 over hashes of 20 to 64 bytes,
# with ones that must fail.
import hashlib, random

random.seed(68030)

CURVES = {
    23: dict(name="P-256", size=32,
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
           0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)),
    24: dict(name="P-384", size=48,
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        g=(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
           0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)),
}

def add(P, Q, p):
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q: l = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else: l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return (x3, (l * (x1 - x3) - y1) % p)

def mul(k, P, p):
    R = None
    while k:
        if k & 1: R = add(R, P, p)
        P = add(P, P, p)
        k >>= 1
    return R

def b(v, n): return v.to_bytes(n, 'big')

def der(r, s):
    def i(v):
        bs = v.to_bytes((v.bit_length() + 8) // 8 or 1, 'big')
        while len(bs) > 1 and bs[0] == 0 and bs[1] < 0x80: bs = bs[1:]
        return bytes([2, len(bs)]) + bs
    body = i(r) + i(s)
    return bytes([0x30, len(body)]) + body if len(body) < 128 else bytes([0x30, 0x81, len(body)]) + body

def carr(name, data):
    s = "static const unsigned char %s[%d] = {" % (name, max(len(data), 1))
    for k, x in enumerate(data or b"\0"):
        s += ("\n\t" if k % 12 == 0 else " ") + "0x%02x," % x
    return s + "\n};\n"

out = ["/* vectors.h - made by gen_vectors.py; known answers for test_kat.c and bench.c */\n"]
rsa = []
for nbytes, e in ((64, 65537), (128, 65537), (128, 3), (255, 65537), (256, 65537),
        (256, 3), (384, 65537), (512, 65537), (512, 17)):
    n = random.getrandbits(8 * nbytes) | (1 << (8 * nbytes - 1)) | 1
    x = random.getrandbits(8 * nbytes) % n
    k = len(rsa)
    out.append(carr("rsa%d_n" % k, b(n, nbytes)))
    out.append(carr("rsa%d_x" % k, b(x, nbytes)))
    out.append(carr("rsa%d_y" % k, b(pow(x, e, n), nbytes)))
    out.append(carr("rsa%d_e" % k, b(e, (e.bit_length() + 7) // 8)))
    rsa.append((k, nbytes, len(b(e, (e.bit_length() + 7) // 8))))
out.append("static const struct rsavec { const unsigned char *n, *e, *x, *y; size_t len, elen; } rsavecs[] = {\n")
for k, nb, el in rsa:
    out.append("\t{ rsa%d_n, rsa%d_e, rsa%d_x, rsa%d_y, %d, %d },\n" % (k, k, k, k, nb, el))
out.append("};\n")

HASHES = (("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64))
ec = []
for cid, c in CURVES.items():
    p, n, size = c['p'], c['n'], c['size']
    for t in range(6):
        d = random.randrange(1, n)
        Q = mul(d, c['g'], p)
        hname, hlen = HASHES[t % 4]
        h = hashlib.new(hname, b"crypt68k %d %d" % (cid, t)).digest()
        e = int.from_bytes(h[:size], 'big') if hlen >= size else int.from_bytes(h, 'big')
        while True:
            k = random.randrange(1, n)
            r = mul(k, c['g'], p)[0] % n
            s = pow(k, -1, n) * (e + r * d) % n
            if r and s: break
        q = b"\x04" + b(Q[0], size) + b(Q[1], size)
        cases = [("good", r, s, h, q, 1), ("n - s", r, n - s, h, q, 1)]
        hb = bytearray(h); hb[0] ^= 1
        cases.append(("other hash", r, s, bytes(hb), q, 0))
        cases.append(("r + 1", (r + 1) % n, s, h, q, 0))
        qb = bytearray(q); qb[-1] ^= 1
        cases.append(("Q off the curve", r, s, h, bytes(qb), 0))
        if t == 0:
            cases.append(("s = 0", r, 0, h, q, 0))
            cases.append(("r = n", n, s, h, q, 0))
        for what, rr, ss, hh, qq, want in cases:
            k = len(ec)
            out.append(carr("ec%d_q" % k, qq))
            out.append(carr("ec%d_h" % k, hh))
            out.append(carr("ec%d_raw" % k, b(rr, size) + b(ss, size)))
            dd = der(rr, ss)
            out.append(carr("ec%d_der" % k, dd))
            ec.append((k, cid, len(hh), len(dd), want, "%s %s/%s" % (c['name'], what, hname)))
out.append("static const struct ecvec { int curve; const unsigned char *q, *h, *raw, *der; size_t hlen, derlen; int want; const char *what; } ecvecs[] = {\n")
for k, cid, hl, dl, want, what in ec:
    out.append("\t{ %d, ec%d_q, ec%d_h, ec%d_raw, ec%d_der, %d, %d, %d, \"%s\" },\n" % (cid, k, k, k, k, hl, dl, want, what))
out.append("};\n")
open("tests/vectors.h", "w").write("".join(out))
print("%d RSA, %d ECDSA vectors" % (len(rsa), len(ec)))
