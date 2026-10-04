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
# X25519 (RFC 7748), checked against the RFC's own answers first
P25519 = 2**255 - 19

def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, 'little')
    x1 = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % P25519; AA = A * A % P25519
        B = (x2 - z2) % P25519; BB = B * B % P25519
        E = (AA - BB) % P25519
        C = (x3 + z3) % P25519; D = (x3 - z3) % P25519
        DA = D * A % P25519; CB = C * B % P25519
        x3 = (DA + CB) ** 2 % P25519
        z3 = x1 * (DA - CB) ** 2 % P25519
        x2 = AA * BB % P25519
        z2 = E * (AA + 121665 * E) % P25519
    if swap: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, 'little')

H = bytes.fromhex
assert x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")) == \
    H("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
alice = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
bob = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
nine = bytes([9]) + bytes(31)
assert x25519(alice, nine) == H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
assert x25519(bob, nine) == H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
assert x25519(alice, x25519(bob, nine)) == H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
k = u = nine
for i in range(1000):
    k, u = x25519(k, u), k
    if i == 0: one = k
assert one == H("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
assert k == H("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

xv = [("RFC 7748 5.2 #1", H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
       H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
      ("RFC 7748 5.2 #2", H("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
       H("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")),
      ("RFC 7748 6.1 Alice's key", alice, nine), ("RFC 7748 6.1 Bob's key", bob, nine),
      ("RFC 7748 6.1 shared", alice, x25519(bob, nine)),
      ("u = 0", random.randbytes(32), bytes(32)),
      ("u = 1", random.randbytes(32), bytes([1]) + bytes(31)),
      ("u = p (not reduced)", random.randbytes(32), P25519.to_bytes(32, 'little')),
      ("u = p + 5", random.randbytes(32), (P25519 + 5).to_bytes(32, 'little')),
      ("u = 2^255 - 1", random.randbytes(32), ((1 << 255) - 1).to_bytes(32, 'little'))]
for i in range(12):
    u = bytearray(random.randbytes(32))
    if i % 3 == 0: u[31] |= 0x80     # the top bit, to be ignored
    xv.append(("random %d" % i, random.randbytes(32), bytes(u)))
for k2, (what, sc, uu) in enumerate(xv):
    out.append(carr("x%d_k" % k2, sc))
    out.append(carr("x%d_u" % k2, uu))
    out.append(carr("x%d_out" % k2, x25519(sc, uu)))
out.append("static const struct xvec { const unsigned char *k, *u, *out; const char *what; } xvecs[] = {\n")
for k2, (what, sc, uu) in enumerate(xv):
    out.append("\t{ x%d_k, x%d_u, x%d_out, \"%s\" },\n" % (k2, k2, k2, what))
out.append("};\n")
out.append(carr("x_iter1", one))
out.append(carr("x_iter1000", k))

open("tests/vectors.h", "w").write("".join(out))
print("%d RSA, %d ECDSA, %d X25519 vectors" % (len(rsa), len(ec), len(xv)))
