# https://www.rfc-editor.org/rfc/rfc8032.html
# https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf

import hashlib
from typing import Self

MODULE: int         = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
MODULE_SUB_2: int   = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
D: int              = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
ORDER: int          = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
ORDERADDINV256: int = 0xefffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c13
B_X: int            = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
B_Y: int            = 0x6666666666666666666666666666666666666666666666666666666666666658
B_Z: int            = 1
B_T: int            = 0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3 # (BX * XY) % P(== 2 ** 255 - 19)
R2: int             = 0x0399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f01
NDASH: int          = 0x9db6c6f26fe9183614e75438ffa36beab1a206f2fdba84ffd2b51da312547e1b

class SHA512:

    s: hashlib.sha512

    def __init__(self, s) -> None:
        self.s = s

    @staticmethod
    def digest_oneshot(bytes: bytes) -> bytes:
        return hashlib.sha512(bytes).digest()

    @staticmethod
    def new() -> Self:
        return SHA512(hashlib.sha512())

    def update(self, bytes: bytes) -> Self:
        self.s.update(bytes)
        return self

    def digest(self) -> bytes:
        return self.s.digest()


class Ed25519Uint:

    @staticmethod
    def mr(a: int) -> int:
        v: int = (a + (((a * NDASH) % (2 ** 256)) * ORDER)) >> 256
        if v >= ORDER:
            return v - ORDER
        else:
            return v

    @staticmethod
    def mod(a: int) -> int:
        return Ed25519Uint.mr(Ed25519Uint.mr(a) * R2)

    @staticmethod
    def add(a: int, b: int) -> int:
        return Ed25519Uint.mod(a + b)

    @staticmethod
    def sub(a: int, b: int) -> int:
        return Ed25519Uint.mod(a - b)

    @staticmethod
    def mul(a: int, b: int) -> int:
        return Ed25519Uint.mod(a * b)

    @staticmethod
    def modp_inv(a: int) -> int:
        return pow(a, MODULE_SUB_2, MODULE)

    @staticmethod
    def from_le_bytes(bytes: bytes) -> int:
        return Ed25519Uint.mod(int.from_bytes(bytes, "little"))

    @staticmethod
    def to_bytes(i: int) -> int:
        return int.to_bytes(i, 32, "little")


class Ed25519Point:

    x: int
    y: int
    z: int
    t: int

    @staticmethod
    def add(p1: Self, p2: Self) -> Self:
        a: int = Ed25519Uint.mul(Ed25519Uint.sub(p1.y, p1.x), Ed25519Uint.sub(p2.y, p2.x))
        b: int = Ed25519Uint.mul(Ed25519Uint.add(p1.y, p1.x), Ed25519Uint.add(p2.y, p2.x))
        c: int = Ed25519Uint.mul(Ed25519Uint.mul(Ed25519Uint.mul(p1.t, 2), D), p2.t)
        d: int = Ed25519Uint.mul(Ed25519Uint.mul(p1.z, 2), p2.z)
        e: int = Ed25519Uint.sub(b, a)
        f: int = Ed25519Uint.sub(d, c)
        g: int = Ed25519Uint.add(d, c)
        h: int = Ed25519Uint.add(b, a)
        return Ed25519Point(
            Ed25519Uint.mul(e, f), # x
            Ed25519Uint.mul(g, h), # y
            Ed25519Uint.mul(f, g), # z
            Ed25519Uint.mul(e, h)  # t
        )

    @staticmethod
    def scalar_mul(p: Self, s: int) -> Self:
        q: Ed25519Point = p.clone()
        v: Ed25519Point = Ed25519Point(0, 1, 1, 0) # Neutral element
        while s > 0:
            if s & 1 == 1:
                v = Ed25519Point.add(v, q)
            q = Ed25519Point.add(q, q)
            s >>= 1
        return v

    def __init__(self, x: int, y: int, z: int, t: int) -> None:
        self.x = x
        self.y = y
        self.z = z
        self.t = t

    @staticmethod
    def clone_base_point() -> Self:
        return Ed25519Point(
            B_X,
            B_Y,
            B_Z,
            B_T
        )

    def clone(self) -> Self:
        return Ed25519Point(
            self.x,
            self.y,
            self.z,
            self.t
        )

    def to_bytes(self) -> bytes: # ENCE
        z_inv: int = Ed25519Uint.modp_inv(self.z)
        x: int = (self.x * z_inv) % MODULE # note that mod "P"
        y: int = (self.y * z_inv) % MODULE # note that mod "P"
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")


class Ed25519:

    def sign(priv_key: bytes, msg: bytes) -> bytes:
        h: bytearray = bytearray(SHA512.digest_oneshot(priv_key))
        h[0]         = h[0]  & 0xf8
        h[31]        = (h[31] & 0x7f) | 0x40
        s: int       = Ed25519Uint.from_le_bytes(h[0:32])
        A: bytes     = Ed25519Point.scalar_mul(Ed25519Point.clone_base_point(), s).to_bytes()
        r: int       = Ed25519Uint.from_le_bytes(SHA512.new().update(h[32:64]).update(msg).digest())
        R: bytes     = Ed25519Point.scalar_mul(Ed25519Point.clone_base_point(), r).to_bytes()
        k: int       = Ed25519Uint.from_le_bytes(SHA512.new().update(R).update(A).update(msg).digest())
        S: bytes     = Ed25519Uint.to_bytes(Ed25519Uint.add(r, Ed25519Uint.mul(k, s)))
        return R + S
