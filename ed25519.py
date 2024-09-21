# https://www.rfc-editor.org/rfc/rfc8032.html
# https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf

import hashlib
from typing import Self

MODULE: int         = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
MODULE_SUB_2: int   = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
D: int              = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
D2: int             = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
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
    def dgst_oneshot(bytes: bytes) -> bytes:
        return hashlib.sha512(bytes).digest()

    @staticmethod
    def new() -> Self:
        return SHA512(hashlib.sha512())

    def upd(self, bytes: bytes) -> Self:
        self.s.update(bytes)
        return self

    def dgst(self) -> bytes:
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
    def add(a: int, b: int) -> int:
        return (a + b) % MODULE # Note that "% module" (not "% ORDER")

    @staticmethod
    def sub(a: int, b: int) -> int:
        return (a - b) % MODULE # Note that "% module" (not "% ORDER")

    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % MODULE # Note that "% module" (not "% ORDER")

    @staticmethod
    def dbl(a: int) -> int:
        return (a << 1) % MODULE # or Ed25519Uint.add(a, a) # Note that "% module" (not "% ORDER")

    @staticmethod
    def mod_order(a: int) -> int:
        return Ed25519Uint.mr(Ed25519Uint.mr(a) * R2)

    @staticmethod
    def add_mod_order(a: int, b: int) -> int:
        return Ed25519Uint.mod_order(a + b)

    @staticmethod
    def mul_mod_order(a: int, b: int) -> int:
        return Ed25519Uint.mod_order(a * b)

    @staticmethod
    def modp_inv(a: int) -> int:
        return pow(a, MODULE_SUB_2, MODULE)

    @staticmethod
    def from_bytes(bytes: bytes) -> int:
        return int.from_bytes(bytes, "little")

    @staticmethod
    def to_bytes(a: int) -> int:
        return int.to_bytes(a, 32, "little")


class Ed25519Point:

    x: int
    y: int
    z: int
    t: int

    @staticmethod
    def eq(p1: Self, p2: Self) -> bool:
        if (Ed25519Uint.sub(Ed25519Uint.mul(p1.x, p2.z), Ed25519Uint.mul(p2.x, p1.z)) != 0 or
            Ed25519Uint.sub(Ed25519Uint.mul(p1.y, p2.z), Ed25519Uint.mul(p2.y, p1.z)) != 0):
            return False
        return True

    @staticmethod
    def add(p1: Self, p2: Self) -> Self:
        a: int = Ed25519Uint.mul(Ed25519Uint.sub(p1.y, p1.x), Ed25519Uint.sub(p2.y, p2.x))
        b: int = Ed25519Uint.mul(Ed25519Uint.add(p1.y, p1.x), Ed25519Uint.add(p2.y, p2.x))
        c: int = Ed25519Uint.mul(Ed25519Uint.mul(p1.t, p2.t), D2)
        d: int = Ed25519Uint.mul(Ed25519Uint.dbl(p1.z), p2.z)
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

    def clone(self) -> Self:
        return Ed25519Point(
            self.x,
            self.y,
            self.z,
            self.t
        )

    @staticmethod
    def new(x: int, y: int, z: int, t: int) -> Self:
        return Ed25519Point(x, y, z, t)

    @staticmethod
    def from_bytes(bytes: bytes) -> tuple[Self, bool]:
        # bytes be most 32 bytes
        y: int    = Ed25519Uint.from_bytes(bytes)
        sign: int = y >> 255
        y         = y & (0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        if not y < MODULE:
            return None, False
        x: int    = 0
        x2: int   = (y * y - 1) *Ed25519Uint.modp_inv(D * y * y + 1)
        if x2 == 0:
            if sign == 1:
                return None, False
            else:
                x = 0
        else:
            x = pow(x2, (MODULE + 3) >> 3, MODULE)
            if (x*x - x2) % MODULE != 0:
                modp_sqrt_m1 = pow(2, (MODULE - 1) >> 2, MODULE)
                x = x * modp_sqrt_m1 % MODULE
            if (x*x - x2) % MODULE != 0:
                return None, False
            if (x & 1) != sign:
                x = MODULE - x
        return Ed25519Point.new(x, y, 1, Ed25519Uint.mul(x, y)), True

    def to_bytes(self) -> bytes: # ENCE
        z_inv: int = Ed25519Uint.modp_inv(self.z)
        x: int = (self.x * z_inv) % MODULE # note that mod "P"
        y: int = (self.y * z_inv) % MODULE # note that mod "P"
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")

B: Ed25519Point = Ed25519Point(B_X, B_Y, B_Z, B_T)


class Ed25519:

    def compute_pubkey(priv_key: bytes) -> bytes:
        h: bytearray = bytearray(SHA512.dgst_oneshot(priv_key))
        h[0]         = h[0]  & 0xf8
        h[31]        = (h[31] & 0x7f) | 0x40
        s: int       = Ed25519Uint.from_bytes(h[0:32]) # no mod
        return Ed25519Point.scalar_mul(B, s).to_bytes()

    def sign(priv_key: bytes, msg: bytes) -> bytes:
        h: bytearray = bytearray(SHA512.dgst_oneshot(priv_key))
        h[0]         = h[0]  & 0xf8
        h[31]        = (h[31] & 0x7f) | 0x40
        s: int       = Ed25519Uint.from_bytes(h[0:32]) # no mod
        A: bytes     = Ed25519Point.scalar_mul(B, s).to_bytes()
        r: int       = Ed25519Uint.mod_order(Ed25519Uint.from_bytes(SHA512.new().upd(h[32:64]).upd(msg).dgst()))
        R: bytes     = Ed25519Point.scalar_mul(B, r).to_bytes()
        k: int       = Ed25519Uint.mod_order(Ed25519Uint.from_bytes(SHA512.new().upd(R).upd(A).upd(msg).dgst()))
        S: int       = Ed25519Uint.add_mod_order(r, Ed25519Uint.mul_mod_order(k, s))
        return R + Ed25519Uint.to_bytes(S)

    def verify(pub_key: bytes, msg: bytes, sign: bytes) -> bool:

        if len(pub_key) != 32 or len(sign) != 64:
            return False

        Rt: tuple[Ed25519Point, bool] = Ed25519Point.from_bytes(sign[0:32])
        if not Rt[1]:
            return False
        R: Ed25519Point               = Rt[0]

        S: int                        = Ed25519Uint.from_bytes(sign[32:64])
        if S > ORDER:
            return False

        At: tuple[Ed25519Point, bool] = Ed25519Point.from_bytes(pub_key)
        if not At[1]:
            return False
        A: Ed25519Point               = At[0]

        k: int                        = Ed25519Uint.mod_order(Ed25519Uint.from_bytes(
            SHA512.new().upd(R.to_bytes()).upd(A.to_bytes()).upd(msg).dgst()
        ))

        return Ed25519Point.eq(
            Ed25519Point.scalar_mul(B, S),
            Ed25519Point.add(Ed25519Point.scalar_mul(A, k), R)
        )