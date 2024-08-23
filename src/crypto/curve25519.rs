use crate::crypto::CryptoError;
use crate::crypto::dh::Dh;
use crate::crypto::hash::Hash;
use crate::crypto::uint::Uint256;
use crate::crypto::sha2::Sha512;

pub struct X25519 {}
pub struct Ed25519 {}

struct Curve25519Point {
    x: Curve25519Uint,
    y: Curve25519Uint,
    z: Curve25519Uint,
    t: Curve25519Uint
}

struct Curve25519Uint {
    buf: Uint256
}

// (2 ^ 255) - 19
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
const MODULE: Uint256 = Uint256{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
]};

// (2 ^ 256) - MODULE
// 0x8000000000000000000000000000000000000000000000000000000000000013
const MODULE_ADDINV256: Uint256 = Uint256{ w: [
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
]};

// (486662 - 2) / 4 == 121665
// 0x000000000000000000000000000000000000000000000000000000000001db41
const A24: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0001db41
]}};

// ((2 ^ 255) - 19) - 2
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
const MODULE_SUB_2: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
]}};

// 9
// 0x0000000000000000000000000000000000000000000000000000000000000009
const U: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009
]}};



// edwords25519 parm

// -(121665 / 121666) == MODULE - ((121665 * mulinv(121666)) % MODULE)
// 37095705934669439343138083508754565189542113879843219016388785533085940283555
// 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
const D: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x52036cee, 0x2b6ffe73, 0x8cc74079, 0x7779e898, 0x00700a4d, 0x4141d8ab, 0x75eb4dca, 0x135978a3
]}};

// (2 ** 252) + 27742317777372353535851937790883648493
// 7237005577332262213973186563042994240857116359379907606001950938285454250989
// 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
const L: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x10000000, 0x00000000, 0x00000000, 0x000000001, 0x4def9de, 0xa2f79cd6, 0x5812631a, 0x5cf5d3ed
]}};

// 15112221349535400772501151409588531511454012693041857206046113283949847762202
// 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
const BX: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x216936d3, 0xcd6e53fe, 0xc0a4e231, 0xfdd6dc5c, 0x692cc760, 0x9525a7b2, 0xc9562d60, 0x8f25d51a
]}};

// 46316835694926478169428394003475163141307993866256225615783033603165251855960
// 0x6666666666666666666666666666666666666666666666666666666666666658
const BY: Curve25519Uint = Curve25519Uint{ buf: Uint256{ w: [
    0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666658
]}};

const X25519_PRIVATE_KEY_LEN: usize   = 32;
const X25519_PUBLIC_KEY_LEN: usize    = 32;
const X25519_SHARED_SECRET_LEN: usize = 32;

const ED25519_PRIVATE_KEY_LEN: usize  = 32;
const ED25519_PUBLIC_KEY_LEN: usize   = 32;
const ED25519_SIGNATURE_LEN: usize    = 64;

fn x25519(out: &mut Curve25519Uint, k: &Curve25519Uint, u: &Curve25519Uint) {

    let x1: Curve25519Uint     = u.clone();
    let mut x2: Curve25519Uint = Curve25519Uint::new_as(1);
    let mut z2: Curve25519Uint = Curve25519Uint::new_as(0);
    let mut x3: Curve25519Uint = u.clone();
    let mut z3: Curve25519Uint = Curve25519Uint::new_as(1);

    let mut t0: Curve25519Uint = Curve25519Uint::new();
    let mut t1: Curve25519Uint = Curve25519Uint::new();
    let mut t2: Curve25519Uint = Curve25519Uint::new();
    let mut t3: Curve25519Uint = Curve25519Uint::new();
    let mut t4: Curve25519Uint = Curve25519Uint::new();

    let mut swap: usize = 0;
    let mut bit: usize;

    let mut j: usize = 31; // i == 0 ? j = 31 : 32;

    for i in 0..8 {

        while j > 0 {

            j = j - 1;

            bit = ((k.buf.w[i] as usize) >> j) & 1;
            swap = swap ^ bit;
            constant_time_swap(swap, &mut x2, &mut x3);
            constant_time_swap(swap, &mut z2, &mut z3);
            swap = bit;

            Curve25519Uint::gadd(&mut t0, &x2, &z2);        // A  = x2 + z2
            Curve25519Uint::gsub(&mut t1, &x2, &z2);        // B  = x2 - z2
            Curve25519Uint::gsqr(&mut t2, &t0);             // AA = A ^ 2
            Curve25519Uint::gsqr(&mut t3, &t1);             // BB = B ^ 2
            Curve25519Uint::gmul(&mut x2, &t2, &t3);        // x2 = AA * BB
            Curve25519Uint::gsub(&mut t4, &t2, &t3);        // E  = AA - BB
            Curve25519Uint::gmul(&mut t3, &A24, &t4);
            Curve25519Uint::gadd_overwrite(&mut t3, &t2);
            Curve25519Uint::gmul(&mut z2, &t4, &t3);        // z2 = E * (AA + a24 * E)
            Curve25519Uint::gsub(&mut t2, &x3, &z3);        // D  = x3 - z3
            Curve25519Uint::gmul_overwrite(&mut t2, &t0);   // DA = D * A
            Curve25519Uint::gadd(&mut t3, &x3, &z3);        // C  = x3 + z3
            Curve25519Uint::gmul_overwrite(&mut t3, &t1);   // CB = C * B
            Curve25519Uint::gadd(&mut t0, &t2, &t3);
            Curve25519Uint::gmul(&mut x3, &t0, &t0);        // x3 = (DA + CB) ^ 2
            Curve25519Uint::gsub(&mut t0, &t2, &t3);
            Curve25519Uint::gsqr_overwrite(&mut t0);
            Curve25519Uint::gmul(&mut z3, &x1, &t0);        // z3 = x1 * (DA - CB) ^ 2

        }

        j = 32;

    }

    constant_time_swap(swap, &mut x2, &mut x3);
    constant_time_swap(swap, &mut z2, &mut z3);

    Curve25519Uint::gpow_overwrite(&mut z2, &MODULE_SUB_2);
    Curve25519Uint::gmul(out, &x2, &z2); // return x2 * (z2 ^ (p - 2))

}

fn constant_time_swap(swap: usize, a: &mut Curve25519Uint, b: &mut Curve25519Uint) {
    let mask: u32 = 0u32.wrapping_sub(swap as u32);
    for i in 0..8 {
        let x: u32 = (a.buf.w[i] ^ b.buf.w[i]) & mask;
        a.buf.w[i] = a.buf.w[i] ^ x;
        b.buf.w[i] = b.buf.w[i] ^ x;
    }
}

impl Dh for X25519 {

    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519_PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough"));
        } else if pub_key.len() < X25519_PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough"));
        }

        let k: Curve25519Uint = Curve25519Uint::try_decode_as_scalar(priv_key).ok()?;
        let mut v: Curve25519Uint = Curve25519Uint::new();
        x25519(&mut v, &k, &U);
        v.try_into_bytes(pub_key)?;

        return None;

    }

    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519_PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough"));
        } else if peer_pub_key.len() < X25519_PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough"));
        } else if shared_secret.len() < X25519_SHARED_SECRET_LEN {
            return Some(CryptoError::new("the length of \"shared_secret\" is not enough"));
        }

        let k: Curve25519Uint = Curve25519Uint::try_decode_as_scalar(priv_key).ok()?;
        let u: Curve25519Uint = Curve25519Uint::try_decode_as_u_coordinate(peer_pub_key).ok()?;
        let mut v: Curve25519Uint = Curve25519Uint::new();
        x25519(&mut v, &k, &u);
        v.try_into_bytes(shared_secret)?;

        return None;

    }

}

// [*1] https://www.rfc-editor.org/rfc/rfc8032.html section-5.1, section-5.1.6, section-2
// [*2] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3002-2020.pdf
// [*3] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf
// [*4] https://github.com/golang/go/blob/master/src/crypto/ed25519/ed25519.go


// - 拡張射影座標系について [*3] pp17

impl Ed25519 {

    // PureEdDSA
    pub fn sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Option<CryptoError> {

        // ENCI: encode int
        // DECI: decode int
        // ENCE: encode point
        // ENC

        // h = SHA-512(k)
        let mut h: [u8; 64] = [0; 64];
        Sha512::digest_oneshot(&priv_key, &mut h);

        // h[0]{0} = 0, h[0]{1} = 0, h[0]{2} = 0, h[31]{7} = 0, h[32]{6} = 1
        h[0]  = h[0]  & 0xf8;
        h[31] = (h[31] & 0x7f) | 0x40;

        // s = DECI(s[0..32])
        let s: Curve25519Uint = Curve25519Uint::try_from_bytes(&h[..32]).ok()?;

        // A = ENCE([s]B)
        let mut a: Curve25519Point = Curve25519Point::new();
        Curve25519Point::scalar_mul(&mut a, &s);

        // r = DECI(SHA-512(h[32..64] || M)) mod L
        let r: Curve25519Uint = {

            let mut sha512 = Sha512::new();
            let mut r: [u8; 64] = [0; 64];
            sha512.update(&h[32..]);
            sha512.update(&msg);
            sha512.digest(&mut r[..]);

            // DECI(SHA-512(h[32..64] || M)) mod L
            // cf. https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf, pp. 9
            let mut buf: [u32; 16] = [
                u32::from_le_bytes(r[60..64].try_into().unwrap()),
                u32::from_le_bytes(r[56..60].try_into().unwrap()),
                u32::from_le_bytes(r[52..56].try_into().unwrap()),
                u32::from_le_bytes(r[48..52].try_into().unwrap()),
                u32::from_le_bytes(r[44..48].try_into().unwrap()),
                u32::from_le_bytes(r[40..44].try_into().unwrap()),
                u32::from_le_bytes(r[36..40].try_into().unwrap()),
                u32::from_le_bytes(r[32..36].try_into().unwrap()),
                u32::from_le_bytes(r[28..32].try_into().unwrap()),
                u32::from_le_bytes(r[24..28].try_into().unwrap()),
                u32::from_le_bytes(r[20..24].try_into().unwrap()),
                u32::from_le_bytes(r[16..20].try_into().unwrap()),
                u32::from_le_bytes(r[12..16].try_into().unwrap()),
                u32::from_le_bytes(r[ 8..12].try_into().unwrap()),
                u32::from_le_bytes(r[ 4.. 8].try_into().unwrap()),
                u32::from_le_bytes(r[ 0.. 4].try_into().unwrap())
            ];

            let mut v: Curve25519Uint = Curve25519Uint::new();
            let mut acc: u64 = 0;


            // mod P じゃなくて mod L

            acc = ((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64;
            buf[8] = buf[8] & 0x7fffffff;
            for i in (0..8).rev() {
                let tmp: u64 = buf[i] as u64;
                acc = acc + (buf[i + 8] as u64) + (tmp << 5) + (tmp << 2) + (tmp << 1);
                buf[i + 8] = (acc & 0xffffffff) as u32;
                acc = acc >> 32;
            }

            acc = (acc << 5) + (acc << 2) + (acc << 1);
            acc = acc + (((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64);
            buf[8] = buf[8] & 0x7fffffff;
            for i in (0..8).rev() {
                acc = acc + (buf[i + 8] as u64);
                v.buf.w[i] = (acc & 0xffffffff) as u32;
                acc = acc >> 32;
            }

            Curve25519Uint::reduce_to_field_element(&mut v);

            v

            // x = a + b * 2^168 + c * 2^336 mod L
            // cf. https://github.com/golang/go/blob/master/src/crypto/internal/edwards25519/scalar.go

        };

        // R = ENCE([r]B)

        // k = DECI(SHA-512(R || A || M)) mod L

        // S = (r + k * s) mod L

        // signature = R || ENCO(S)    <- ENCO? typo?

        return None;

    }

}

impl Curve25519Point {

    pub fn scalar_mul(dst: &mut Curve25519Point, scalar: &Curve25519Uint) {

    }

    pub fn add(dst: &mut Curve25519Point, lhs: &Curve25519Point, rhs: &Curve25519Point) {

        let mut t1: Curve25519Uint = Curve25519Uint::new();
        let mut t2: Curve25519Uint = Curve25519Uint::new();
        let mut t3: Curve25519Uint = Curve25519Uint::new();
        let mut t4: Curve25519Uint = Curve25519Uint::new();
        let mut t5: Curve25519Uint = Curve25519Uint::new();

        // A = (Y1-X1)*(Y2-X2)
        Curve25519Uint::gsub(&mut t5, &lhs.y, &lhs.x);
        Curve25519Uint::gsub(&mut t1, &rhs.y, &rhs.x);
        Curve25519Uint::gmul_overwrite(&mut t5, &t2);

        // B = (Y1+X1)*(Y2+X2)
        Curve25519Uint::gadd(&mut t4, &lhs.y, &lhs.x);
        Curve25519Uint::gadd(&mut t1, &rhs.y, &rhs.x);
        Curve25519Uint::gmul_overwrite(&mut t4, &t1);

        // E = B-A
        Curve25519Uint::gsub(&mut t1, &t4, &t5);

        // H = B+A
        Curve25519Uint::gadd_overwrite(&mut t4, &t5);

        // C = T1*2*d*T2
        Curve25519Uint::gmul(&mut t5, &lhs.t, &rhs.t);
        Curve25519Uint::gmul_overwrite(&mut t5, &Curve25519Uint::new_as(2));
        Curve25519Uint::gmul_overwrite(&mut t5, &D);

        // D = Z1*2*Z2
        Curve25519Uint::gmul(&mut t3, &lhs.z, &rhs.z);
        Curve25519Uint::gmul_overwrite(&mut t3, &Curve25519Uint::new_as(2));

        // F = D-C
        Curve25519Uint::gsub(&mut t2, &t3, &t5);

        // G = D+C
        Curve25519Uint::gadd_overwrite(&mut t3, &t5);

        // X3 = E*F
        Curve25519Uint::gmul(&mut dst.x, &t1, &t2);

        // Y3 = G*H
        Curve25519Uint::gmul(&mut dst.y, &t3, &t4);

        // Z3 = F*G
        Curve25519Uint::gmul(&mut dst.z, &t2, &t3);

        // T3 = E*H
        Curve25519Uint::gmul(&mut dst.t, &t1, &t4);

        // A = (Y1-X1)*(Y2-X2)
        // B = (Y1+X1)*(Y2+X2)
        // C = T1*2*d*T2
        // D = Z1*2*Z2
        // E = B-A
        // F = D-C
        // G = D+C
        // H = B+A
        // X3 = E*F
        // Y3 = G*H
        // T3 = E*H
        // Z3 = F*G

    }

    pub fn dbl(dst: &mut Curve25519Point, src: &Curve25519Point) {




    }

}



impl Curve25519Uint {

    pub fn new() -> Curve25519Uint {
        return Curve25519Uint{ buf: Uint256{ w: [0; 8] }};
    }

    pub fn new_as(u: usize) -> Curve25519Uint {
        return Curve25519Uint{ buf: Uint256::new_as(u) };
    }

    fn try_from_bytes_inner(b: &[u8]) -> Result<Curve25519Uint, CryptoError> {

        if b.len() < 32 {
            return Err(CryptoError::new("the length of bytes \"b\" is not enough"));
        }

        return Ok(Curve25519Uint{ buf: Uint256{ w: [
            u32::from_le_bytes(b[28..32].try_into().unwrap()),
            u32::from_le_bytes(b[24..28].try_into().unwrap()),
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
            u32::from_le_bytes(b[16..20].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
            u32::from_le_bytes(b[ 8..12].try_into().unwrap()),
            u32::from_le_bytes(b[ 4.. 8].try_into().unwrap()),
            u32::from_le_bytes(b[ 0.. 4].try_into().unwrap())
        ]}});

    }

    pub fn try_from_bytes(b: &[u8]) -> Result<Curve25519Uint, CryptoError> {
        let v: Curve25519Uint = Curve25519Uint::try_from_bytes_inner(b)?;
        return if Uint256::lt(&v.buf, &MODULE) {
            Ok(v)
        } else {
            Err(CryptoError::new(
                "the bytes \"b\" was decoded as a number greater than or equal the modulo prime"
            ))
        }
    }

    pub fn try_decode_as_scalar(b: &[u8]) -> Result<Curve25519Uint, CryptoError> {
        let mut v: Curve25519Uint = Curve25519Uint::try_from_bytes_inner(b)?;
        v.buf.w[0] = v.buf.w[0] & 0x7fffffff;
        v.buf.w[0] = v.buf.w[0] | 0x40000000;
        v.buf.w[7] = v.buf.w[7] & 0xfffffff8;
        return Ok(v);
    }

    pub fn try_decode_as_u_coordinate(b: &[u8]) -> Result<Curve25519Uint, CryptoError> {
        let mut v: Curve25519Uint = Curve25519Uint::try_from_bytes_inner(b)?;
        v.buf.w[0] = v.buf.w[0] & 0x7fffffff;
        Curve25519Uint::reduce_to_field_element(&mut v);
        return Ok(v);
    }

    pub fn try_into_bytes(&self, b: &mut [u8]) -> Option<CryptoError> {

        if b.len() < 32 {
            return Some(CryptoError::new("the length of bytes \"b\" is not enough"));
        }

        for i in 0..8 {
            let j: usize = i << 2;
            b[j + 0] = (self.buf.w[7 - i] >>  0) as u8;
            b[j + 1] = (self.buf.w[7 - i] >>  8) as u8;
            b[j + 2] = (self.buf.w[7 - i] >> 16) as u8;
            b[j + 3] = (self.buf.w[7 - i] >> 24) as u8;
        }

        return None;

    }

    pub fn gadd(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gadd_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn gsub(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gsub_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn gmul(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gmul_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn gsqr(dst: &mut Self, src: &Self) { unsafe {
        Self::gmul_raw(dst as *mut Self, src as *const Self, src as *const Self);
    }}

    pub fn gpow(dst: &mut Self, base: &Self, exp: &Self) { unsafe {
        Self::gpow_raw(dst as *mut Self, base as *const Self, exp as *const Self);
    }}

    pub fn gadd_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gadd_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gsub_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gsub_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gmul_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gmul_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gsqr_overwrite(src_dst: &mut Self) { unsafe {
        Self::gmul_raw(src_dst as *mut Self, src_dst as *const Self, src_dst as *const Self);
    }}

    pub fn gpow_overwrite(base_dst: &mut Self, exp: &Self) { unsafe {
        Self::gpow_raw(base_dst as *mut Self, base_dst as *const Self, exp as *const Self);
    }}

    unsafe fn gadd_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {
        Uint256::add(&mut (*dst).buf, &(*lhs).buf, &(*rhs).buf);
        Self::reduce_to_field_element(&mut (*dst));
    }

    unsafe fn gsub_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut rhs_addinv256: Uint256 = Uint256::new();
        Self::addinv256(&mut rhs_addinv256, &(*rhs).buf);
        Uint256::add(&mut (*dst).buf, &(*lhs).buf, &rhs_addinv256);
        Self::reduce_to_field_element(&mut (*dst));
    }

    unsafe fn gmul_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {

        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;
        let mut k: usize;

        for i in 0..8 {
            for j in 0..8 {

                let tmp: u64 = ((*lhs).buf.w[i] as u64) * ((*rhs).buf.w[j] as u64);

                acc = tmp & 0xffffffff;
                for k in (0..(i + j + 2)).rev() {
                    acc = acc + (buf[k] as u64);
                    buf[k] = (acc & 0xffffffff) as u32;
                    acc = acc >> 32;
                }

                acc = tmp >> 32;
                for k in (0..(i + j + 1)).rev() {
                    acc = acc + (buf[k] as u64);
                    buf[k] = (acc & 0xffffffff) as u32;
                    acc = acc >> 32;
                }

            }
        }

        acc = ((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64;
        buf[8] = buf[8] & 0x7fffffff;
        for i in (0..8).rev() {
            let tmp: u64 = buf[i] as u64;
            acc = acc + (buf[i + 8] as u64) + (tmp << 5) + (tmp << 2) + (tmp << 1);
            buf[i + 8] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }

        acc = (acc << 5) + (acc << 2) + (acc << 1);
        acc = acc + (((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64);
        buf[8] = buf[8] & 0x7fffffff;
        for i in (0..8).rev() {
            acc = acc + (buf[i + 8] as u64);
            (*dst).buf.w[i] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }

        Self::reduce_to_field_element(&mut (*dst));

    }

    unsafe fn gpow_raw(dst: *mut Self, base: *const Self, exp: *const Self) {

        let mut a: Self = Self::new_as(1);
        let mut b: Self = (*base).clone();

        for i in 0..8 {
            let mut s: u32 = 0x80000000;
            loop {

                if ((*exp).buf.w[i] & s) == 0 {
                    Self::gmul_overwrite(&mut b, &a);
                    Self::gsqr_overwrite(&mut a);
                } else {
                    Self::gmul_overwrite(&mut a, &b);
                    Self::gsqr_overwrite(&mut b);
                }

                s = s >> 1;

                if s == 0 {
                    break;
                }

            }
        }

        for i in 0..8 {
            (*dst).buf.w[i] = a.buf.w[i];
        }

    }

    pub fn reduce_to_field_element(v: &mut Self) {
        let mask: u32    = if Uint256::lt(&v.buf, &MODULE) { 0u32 } else { u32::MAX };
        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (v.buf.w[u] as u64) + ((MODULE_ADDINV256.w[u] & mask) as u64);
            v.buf.w[u] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

    fn addinv256(dst: &mut Uint256, src: &Uint256) {
        let mut acc: u64 = 1;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + ((!(src.w[u] as u64)) & 0xffffffff) + (MODULE.w[u] as u64);
            dst.w[u] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

}

impl Clone for Curve25519Uint {

    fn clone(&self) -> Self {
        return Self{ buf: Uint256{ w: [
            self.buf.w[0], self.buf.w[1], self.buf.w[2], self.buf.w[3],
            self.buf.w[4], self.buf.w[5], self.buf.w[6], self.buf.w[7],
        ]}};
    }

}
