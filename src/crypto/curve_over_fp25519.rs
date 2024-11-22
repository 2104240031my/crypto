use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;

pub struct Fp25519Uint {
    pub words: [u32; 8]
}

pub struct Edwards25519Point {
    pub x: Fp25519Uint,
    pub y: Fp25519Uint,
    pub z: Fp25519Uint,
    pub t: Fp25519Uint
}

// (2 ** 255) - 19
// 57896044618658097711785492504343953926634992332820282019728792003956564819949
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
pub const P: Fp25519Uint = Fp25519Uint{ words: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
]};

// (2 ** 252) + 27742317777372353535851937790883648493
// 7237005577332262213973186563042994240857116359379907606001950938285454250989
// 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
pub const Q: Fp25519Uint = Fp25519Uint{ words: [
    0x10000000, 0x00000000, 0x00000000, 0x00000000, 0x14def9de, 0xa2f79cd6, 0x5812631a, 0x5cf5d3ed
]};

// (486662 - 2) / 4 == 121665
// 0x000000000000000000000000000000000000000000000000000000000001db41
pub const A24: Fp25519Uint = Fp25519Uint{ words: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0001db41
]};

// 9
// 0x0000000000000000000000000000000000000000000000000000000000000009
pub const U: Fp25519Uint = Fp25519Uint{ words: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009
]};

pub const B: Edwards25519Point = Edwards25519Point{

    // 15112221349535400772501151409588531511454012693041857206046113283949847762202
    // 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    x: Fp25519Uint{ words: [
        0x216936d3, 0xcd6e53fe, 0xc0a4e231, 0xfdd6dc5c, 0x692cc760, 0x9525a7b2, 0xc9562d60, 0x8f25d51a
    ]},

    // 46316835694926478169428394003475163141307993866256225615783033603165251855960
    // 0x6666666666666666666666666666666666666666666666666666666666666658
    y: Fp25519Uint{ words: [
        0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666658
    ]},

    // 1
    // 0x0000000000000000000000000000000000000000000000000000000000000001
    z: Fp25519Uint{ words: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    ]},

    // 46827403850823179245072216630277197565144205554125654976674165829533817101731
    // 0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3
    t: Fp25519Uint{ words: [
        0x67875f0f, 0xd78b7665, 0x66ea4e8e, 0x64abe37d, 0x20f09f80, 0x775152f5, 0x6dde8ab3, 0xa5b7dda3
    ]}

};

impl Fp25519Uint {

    pub fn new() -> Self {
        return Self{ words: [0; 8] };
    }

    pub fn from_usize(u: usize) -> Self {
        return Self{ words: [0, 0, 0, 0, 0, 0, (u as u64 >> 32) as u32, u as u32] };
    }

    pub fn from_u32_array(a: [u32; 8]) -> Self {
        return Self{ words: [a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]] };
    }

    pub fn try_from_bytes(b: &[u8]) -> Result<Self, CryptoError> {

        if b.len() != 32 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        return Ok(Self{ words: [
            ((b[31] as u32) << 24) | ((b[30] as u32) << 16) | ((b[29] as u32) << 8) | (b[28] as u32),
            ((b[27] as u32) << 24) | ((b[26] as u32) << 16) | ((b[25] as u32) << 8) | (b[24] as u32),
            ((b[23] as u32) << 24) | ((b[22] as u32) << 16) | ((b[21] as u32) << 8) | (b[20] as u32),
            ((b[19] as u32) << 24) | ((b[18] as u32) << 16) | ((b[17] as u32) << 8) | (b[16] as u32),
            ((b[15] as u32) << 24) | ((b[14] as u32) << 16) | ((b[13] as u32) << 8) | (b[12] as u32),
            ((b[11] as u32) << 24) | ((b[10] as u32) << 16) | ((b[ 9] as u32) << 8) | (b[ 8] as u32),
            ((b[ 7] as u32) << 24) | ((b[ 6] as u32) << 16) | ((b[ 5] as u32) << 8) | (b[ 4] as u32),
            ((b[ 3] as u32) << 24) | ((b[ 2] as u32) << 16) | ((b[ 1] as u32) << 8) | (b[ 0] as u32)
        ]});

    }

    pub fn try_from_bytes_as_scalar(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes(b)?;
        v.words[0] = v.words[0] & 0x7fffffff;
        v.words[0] = v.words[0] | 0x40000000;
        v.words[7] = v.words[7] & 0xfffffff8;
        return Ok(v);
    }

    pub fn try_from_bytes_as_u_coordinate(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes(b)?;
        v.words[0] = v.words[0] & 0x7fffffff;
        fp25519_uint_wrap(0, &mut v);
        return Ok(v);
    }

    pub fn try_into_bytes(&self, b: &mut [u8]) -> Result<(), CryptoError> {

        if b.len() != 32 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        for i in (0..8).rev() {
            let j: usize = (7 - i) << 2;
            b[j + 0] = (self.words[i] >>  0) as u8;
            b[j + 1] = (self.words[i] >>  8) as u8;
            b[j + 2] = (self.words[i] >> 16) as u8;
            b[j + 3] = (self.words[i] >> 24) as u8;
        }

        return Ok(());

    }

    pub fn clone(&self) -> Self {
        return Self{ words: [
            self.words[0],
            self.words[1],
            self.words[2],
            self.words[3],
            self.words[4],
            self.words[5],
            self.words[6],
            self.words[7]
        ]};
    }

    pub fn constant_time_swap(a: &mut Self, b: &mut Self, swap: bool) {
        let mask: u32 = if swap { u32::MAX } else { 0 };
        for i in 0..8 {
            let temp: u32 = (a.words[i] ^ b.words[i]) & mask;
            a.words[i] = a.words[i] ^ temp;
            b.words[i] = b.words[i] ^ temp;
        }
    }

    // lhs == rhs
    pub fn eq(lhs: &Self, rhs: &Self) -> bool {
        let mut acc: u64 = 0;
        for i in 0..8 {
            acc = acc | ((lhs.words[i] as u64) ^ (rhs.words[i] as u64));
        }
        return acc == 0;
    }

    // lhs < rhs
    pub fn lt(lhs: &Self, rhs: &Self) -> bool {
        return fp25519_uint_lt(0, lhs, 0, rhs);
    }

    // res = val + 1 mod p
    pub fn ginc(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_ginc(res as *mut Self, val as *const Self);
    }}

    // res = val - 1 mod p
    pub fn gdec(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_gdec(res as *mut Self, val as *const Self);
    }}

    // res = lhs + rhs mod p
    pub fn gadd(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gadd(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = val * 2 mod p
    pub fn gdbl(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_gadd(res as *mut Self, val as *const Self, val as *const Self);
    }}

    // res = lhs - rhs mod p
    pub fn gsub(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gsub(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs * rhs mod p
    pub fn gmul(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gmul(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = val * val mod p
    pub fn gsqr(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_gmul(res as *mut Self, val as *const Self, val as *const Self);
    }}

    // res = lhs / rhs mod p
    pub fn gdiv(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gdiv(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = base ** exp mod p
    pub fn gpow(res: &mut Self, base: &Self, exp: &Self) { unsafe {
        fp25519_uint_gpow(res as *mut Self, base as *const Self, exp as *const Self);
    }}

    // res = p - val mod p
    pub fn gaddinv(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_gaddinv(res as *mut Self, val as *const Self);
    }}

    // res = val ** -1 mod p
    pub fn gmulinv(res: &mut Self, val: &Self) { unsafe {
        fp25519_uint_gmulinv(res as *mut Self, val as *const Self);
    }}

    // res++ mod p
    pub fn ginc_assign(res: &mut Self) { unsafe {
        fp25519_uint_ginc(res as *mut Self, res as *const Self);
    }}

    // res-- mod p
    pub fn gdec_assign(res: &mut Self) { unsafe {
        fp25519_uint_gdec(res as *mut Self, res as *const Self);
    }}

    // res = res + rhs mod p
    pub fn gadd_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gadd(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * 2 mod p
    pub fn gdbl_assign(res: &mut Self) { unsafe {
        fp25519_uint_gadd(res as *mut Self, res as *const Self, res as *const Self);
    }}

    // res = res - rhs mod p
    pub fn gsub_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gsub(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * rhs mod p
    pub fn gmul_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gmul(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * res mod p
    pub fn gsqr_assign(res: &mut Self) { unsafe {
        fp25519_uint_gmul(res as *mut Self, res as *const Self, res as *const Self);
    }}

    // res = res / rhs mod p
    pub fn gdiv_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gdiv(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res ** exp mod p
    pub fn gpow_assign(res: &mut Self, exp: &Self) { unsafe {
        fp25519_uint_gpow(res as *mut Self, res as *const Self, exp as *const Self);
    }}

    // res = p - val mod p
    pub fn gaddinv_assign(res: &mut Self) { unsafe {
        fp25519_uint_gaddinv(res as *mut Self, res as *const Self);
    }}

    // res = val ** -1 mod p
    pub fn gmulinv_assign(res: &mut Self) { unsafe {
        fp25519_uint_gmulinv(res as *mut Self, res as *const Self);
    }}

    // res = lhs + rhs mod q
    pub fn gadd_mod_order(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gadd_mod_order(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs * rhs mod q
    pub fn gmul_mod_order(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp25519_uint_gmul_mod_order(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = res + rhs mod q
    pub fn gadd_assign_mod_order(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gadd_mod_order(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * rhs mod q
    pub fn gmul_assign_mod_order(res: &mut Self, rhs: &Self) { unsafe {
        fp25519_uint_gmul_mod_order(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = b512 mod q
    pub fn mod_order(res: &mut Self, b512: &[u32]) {

        let mut t: Self = Self::new();
        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;

        fp25519_uint_mr(&mut t, b512);

        for i in 0..8 {
            for j in 0..8 {

                let temp: u64 = (t.words[i] as u64) * (RR.words[j] as u64);

                acc = temp & 0xffffffff;
                for k in (0..(i + j + 2)).rev() {
                    acc = acc + (buf[k] as u64);
                    buf[k] = acc as u32;
                    acc = acc >> 32;
                }

                acc = temp >> 32;
                for k in (0..(i + j + 1)).rev() {
                    acc = acc + (buf[k] as u64);
                    buf[k] = acc as u32;
                    acc = acc >> 32;
                }

            }
        }

        fp25519_uint_mr(res, &buf[..]);

        let mask: u32 = if fp25519_uint_lt(0, res, 0, &Q8) { 0 } else { u32::MAX };
        acc = 0;
        for i in (0..8).rev() {
            acc = acc + (res.words[i] as u64) + ((Q8_ADDINV.words[i] & mask) as u64);
            res.words[i] = acc as u32;
            acc = acc >> 32;
        }

        let mask: u32 = if fp25519_uint_lt(0, res, 0, &Q4) { 0 } else { u32::MAX };
        acc = 0;
        for i in (0..8).rev() {
            acc = acc + (res.words[i] as u64) + ((Q4_ADDINV.words[i] & mask) as u64);
            res.words[i] = acc as u32;
            acc = acc >> 32;
        }

        let mask: u32 = if fp25519_uint_lt(0, res, 0, &Q2) { 0 } else { u32::MAX };
        acc = 0;
        for i in (0..8).rev() {
            acc = acc + (res.words[i] as u64) + ((Q2_ADDINV.words[i] & mask) as u64);
            res.words[i] = acc as u32;
            acc = acc >> 32;
        }

        fp25519_uint_wrap_mod_order(0, res);

    }

}

impl Edwards25519Point {

    pub fn new() -> Self {
        return Self{
            x: Fp25519Uint::new(),
            y: Fp25519Uint::new(),
            z: Fp25519Uint::new(),
            t: Fp25519Uint::new()
        };
    }

    pub fn new_neutral_point() -> Self {
        return Self{
            x: Fp25519Uint::from_usize(0),
            y: Fp25519Uint::from_usize(1),
            z: Fp25519Uint::from_usize(1),
            t: Fp25519Uint::from_usize(0)
        };
    }

    pub fn try_from_bytes(b: &[u8]) -> Result<Self, CryptoError> {

        let mut y = Fp25519Uint::try_from_bytes(b)?;
        y.words[0] = y.words[0] & 0x7fffffff;
        let sign: u32 = (b[31] >> 7) as u32;

        if !Fp25519Uint::lt(&y, &P) {
            return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
        }

        let mut x  = Fp25519Uint::new();
        let mut x2 = Fp25519Uint::new();
        let mut t1 = Fp25519Uint::new();
        let mut t2 = Fp25519Uint::new();

        Fp25519Uint::gsqr(&mut t1, &y);
        Fp25519Uint::gmul(&mut t2, &D, &t1);
        Fp25519Uint::gdec_assign(&mut t1);
        Fp25519Uint::ginc_assign(&mut t2);
        Fp25519Uint::gdiv(&mut x2, &t1, &t2);

        let mut acc: u32;

        acc = 0;
        for i in 0..8 {
            acc = acc | x2.words[i];
        }
        if acc == 0 {
            if sign == 1 {
                return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
            } else {
                return Ok(Self{
                    x: Fp25519Uint::from_usize(0),
                    y: y,
                    z: Fp25519Uint::from_usize(1),
                    t: Fp25519Uint::from_usize(0)
                });
            }
        }

        Fp25519Uint::gpow(&mut x, &x2, &P_ADD3_DIV8);
        Fp25519Uint::gaddinv(&mut t2, &x2);

        Fp25519Uint::gsqr(&mut t1, &x);
        Fp25519Uint::gadd_assign(&mut t1, &t2);
        acc = 0;
        for i in 0..8 {
            acc = acc | t1.words[i];
        }
        if acc != 0 {
            Fp25519Uint::gmul_assign(&mut x, &P_SQRT_M1);
        }

        Fp25519Uint::gsqr(&mut t1, &x);
        Fp25519Uint::gadd_assign(&mut t1, &t2);
        acc = 0;
        for i in 0..8 {
            acc = acc | t1.words[i];
        }
        if acc != 0 {
            return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
        }

        if (x.words[7] & 1) != sign {
            Fp25519Uint::gaddinv_assign(&mut x);
        }

        Fp25519Uint::gmul(&mut t1, &x, &y);
        return Ok(Self{
            x: x,
            y: y,
            z: Fp25519Uint::from_usize(1),
            t: t1
        });

    }

    pub fn try_into_bytes(&self, b: &mut [u8]) -> Result<(), CryptoError> {

        let mut t1: Fp25519Uint = Fp25519Uint::new();
        let mut t2: Fp25519Uint = Fp25519Uint::new();

        Fp25519Uint::gmulinv(&mut t1, &self.z);
        Fp25519Uint::gmul(&mut t2, &self.x, &t1);
        Fp25519Uint::gmul_assign(&mut t1, &self.y);

        t1.try_into_bytes(b)?;
        b[31] = b[31] | (((t2.words[7] & 1) << 7) as u8);

        return Ok(());

    }

    pub fn clone(&self) -> Self {
        return Self{
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
            t: self.t.clone()
        };
    }

    pub fn constant_time_swap(a: &mut Self, b: &mut Self, swap: bool) {
        Fp25519Uint::constant_time_swap(&mut a.x, &mut b.x, swap);
        Fp25519Uint::constant_time_swap(&mut a.y, &mut b.y, swap);
        Fp25519Uint::constant_time_swap(&mut a.z, &mut b.z, swap);
        Fp25519Uint::constant_time_swap(&mut a.t, &mut b.t, swap);
    }

    pub fn eq(lhs: &Self, rhs: &Self) -> bool {

        let mut t1: Fp25519Uint = Fp25519Uint::new();
        let mut t2: Fp25519Uint = Fp25519Uint::new();
        let mut acc: u32 = 0;

        Fp25519Uint::gmul(&mut t1, &lhs.x, &rhs.z);
        Fp25519Uint::gmul(&mut t2, &rhs.x, &lhs.z);
        Fp25519Uint::gsub_assign(&mut t1, &t2);
        for i in 0..8 {
            acc = acc | t1.words[i];
        }

        Fp25519Uint::gmul(&mut t1, &lhs.y, &rhs.z);
        Fp25519Uint::gmul(&mut t2, &rhs.y, &lhs.z);
        Fp25519Uint::gsub_assign(&mut t1, &t2);
        for i in 0..8 {
            acc = acc | t1.words[i];
        }

        return acc == 0;

    }

    pub fn add(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        edwards25519_point_add(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn dbl(res: &mut Self, val: &Self) { unsafe {
        edwards25519_point_add(res as *mut Self, val as *const Self, val as *const Self);
    }}

    pub fn add_assign(res: &mut Self, rhs: &Self) { unsafe {
        edwards25519_point_add(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    pub fn dbl_assign(res: &mut Self) { unsafe {
        edwards25519_point_add(res as *mut Self, res as *const Self, res as *const Self);
    }}

    pub fn scalar_mul(res: &mut Self, p: &Self, s: &Fp25519Uint) { unsafe {
        edwards25519_point_scalar_mul(res as *mut Self, p as *const Self, s);
    }}

    pub fn scalar_mul_assign(res: &mut Self, s: &Fp25519Uint) { unsafe {
        edwards25519_point_scalar_mul(res as *mut Self, res as *const Self, s);
    }}

}

// (2 ** 256) - p
// 0x8000000000000000000000000000000000000000000000000000000000000013
const P_ADDINV: Fp25519Uint = Fp25519Uint{ words: [
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
]};

// p - 1
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
const P_SUB1: Fp25519Uint = Fp25519Uint{ words: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffec
]};

// p - 2
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
const P_SUB2: Fp25519Uint = Fp25519Uint{ words: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
]};

// (p + 3) / 8
// 0x0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
const P_ADD3_DIV8: Fp25519Uint = Fp25519Uint{ words: [
    0x0fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe
]};

// 2 ** ((p - 1) / 4) mod p
// 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
const P_SQRT_M1: Fp25519Uint = Fp25519Uint{ words: [
    0x2b832480, 0x4fc1df0b, 0x2b4d0099, 0x3dfbd7a7, 0x2f431806, 0xad2fe478, 0xc4ee1b27, 0x4a0ea0b0
]};

// (2 ** 256) - Q
// 0xefffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c13
const Q_ADDINV: Fp25519Uint = Fp25519Uint{ words: [
    0xefffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xeb210621, 0x5d086329, 0xa7ed9ce5, 0xa30a2c13
]};

// Q * 2
// 0x2000000000000000000000000000000029bdf3bd45ef39acb024c634b9eba7da
const Q2: Fp25519Uint = Fp25519Uint{ words: [
    0x20000000, 0x00000000, 0x00000000, 0x00000000, 0x29bdf3bd, 0x45ef39ac, 0xb024c634, 0xb9eba7da
]};

// (2 ** 256) - Q2
// 0xdfffffffffffffffffffffffffffffffd6420c42ba10c6534fdb39cb46145826
const Q2_ADDINV: Fp25519Uint = Fp25519Uint{ words: [
    0xdfffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xd6420c42, 0xba10c653, 0x4fdb39cb, 0x46145826
]};

// Q * 4
// 0x40000000000000000000000000000000537be77a8bde735960498c6973d74fb4
const Q4: Fp25519Uint = Fp25519Uint{ words: [
    0x40000000, 0x00000000, 0x00000000, 0x00000000, 0x537be77a, 0x8bde7359, 0x60498c69, 0x73d74fb4
]};

// (2 ** 256) - Q4
// 0xbfffffffffffffffffffffffffffffffac84188574218ca69fb673968c28b04c
const Q4_ADDINV: Fp25519Uint = Fp25519Uint{ words: [
    0xbfffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xac841885, 0x74218ca6, 0x9fb67396, 0x8c28b04c
]};

// Q * 8
// 0x80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f68
const Q8: Fp25519Uint = Fp25519Uint{ words: [
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0xa6f7cef5, 0x17bce6b2, 0xc09318d2, 0xe7ae9f68
]};

// (2 ** 256) - Q8
// 0x7fffffffffffffffffffffffffffffff5908310ae843194d3f6ce72d18516098
const Q8_ADDINV: Fp25519Uint = Fp25519Uint{ words: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x5908310a, 0xe843194d, 0x3f6ce72d, 0x18516098
]};

// 71336056475231800826343715077027849978041630819377026201054086228062141447707
// 0x9db6c6f26fe9183614e75438ffa36beab1a206f2fdba84ffd2b51da312547e1b
const ND: Fp25519Uint = Fp25519Uint{ words: [
    0x9db6c6f2, 0x6fe91836, 0x14e75438, 0xffa36bea, 0xb1a206f2, 0xfdba84ff, 0xd2b51da3, 0x12547e1b
]};

// 1627715501170711445284395025044413883736156588369414752970002579683115011841
// 0x0399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f01
const RR: Fp25519Uint = Fp25519Uint{ words: [
    0x0399411b, 0x7c309a3d, 0xceec73d2, 0x17f5be65, 0xd00e1ba7, 0x68859347, 0xa40611e3, 0x449c0f01
]};

// -(121665 / 121666) == p - ((121665 * mulinv(121666)) % p)
// 37095705934669439343138083508754565189542113879843219016388785533085940283555
// 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
const D: Fp25519Uint = Fp25519Uint{ words: [
    0x52036cee, 0x2b6ffe73, 0x8cc74079, 0x7779e898, 0x00700a4d, 0x4141d8ab, 0x75eb4dca, 0x135978a3
]};

// d * 2 mod p
// 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
const D2: Fp25519Uint = Fp25519Uint{ words: [
    0x2406d9dc, 0x56dffce7, 0x198e80f2, 0xeef3d130, 0x00e0149a, 0x8283b156, 0xebd69b94, 0x26b2f159
]};

fn fp25519_uint_lt(lhs_carry: u64, lhs: &Fp25519Uint, rhs_carry: u64, rhs: &Fp25519Uint) -> bool {

    let mut bit: u64 = 1;
    let mut l: u64 = lhs_carry << 8; // summary of left
    let mut r: u64 = rhs_carry << 8; // summary of right

    for i in (0..8).rev() {
        let gt_mask: u64 = if lhs.words[i] > rhs.words[i] { u64::MAX } else { 0 };
        let lt_mask: u64 = if lhs.words[i] < rhs.words[i] { u64::MAX } else { 0 };
        l = l | (bit & gt_mask);
        r = r | (bit & lt_mask);
        bit = bit << 1;
    }

    return l < r;

}

// res = res - if res < p { 0 } else { p }
fn fp25519_uint_wrap(res_carry: u64, res: &mut Fp25519Uint) {
    let mask: u32 = if fp25519_uint_lt(res_carry, &res, 0, &P) { 0 } else { u32::MAX };
    let mut acc: u64 = 0;
    for i in (0..8).rev() {
        acc = acc + (res.words[i] as u64) + ((P_ADDINV.words[i] & mask) as u64);
        res.words[i] = acc as u32;
        acc = acc >> 32;
    }
}

// res = res - if res < l { 0 } else { q }
fn fp25519_uint_wrap_mod_order(res_carry: u64, res: &mut Fp25519Uint) {
    let mask: u32 = if fp25519_uint_lt(res_carry, &res, 0, &Q) { 0 } else { u32::MAX };
    let mut acc: u64 = 0;
    for i in (0..8).rev() {
        acc = acc + (res.words[i] as u64) + ((Q_ADDINV.words[i] & mask) as u64);
        res.words[i] = acc as u32;
        acc = acc >> 32;
    }
}

fn fp25519_uint_mr(res: &mut Fp25519Uint, b512: &[u32]) {

    let mut t: Fp25519Uint = Fp25519Uint::from_usize(0);
    let mut buf: [u32; 16] = [0; 16];
    let mut acc: u64;

    for i in 0..8 {
        for j in 0..8 {

            let n: usize = i + j + 2;

            if n >= 8 {

                let temp: u64 = (b512[i + 8] as u64) * (ND.words[j] as u64);

                acc = temp & 0xffffffff;
                for k in (0..(n - 8)).rev() {
                    acc = acc + (t.words[k] as u64);
                    t.words[k] = acc as u32;
                    acc = acc >> 32;
                }

                if n >= 9 {
                    acc = temp >> 32;
                    for k in (0..(n - 9)).rev() {
                        acc = acc + (t.words[k] as u64);
                        t.words[k] = acc as u32;
                        acc = acc >> 32;
                    }
                }

            }

        }
    }

    for i in 0..8 {
        for j in 0..8 {

            let temp: u64 = (t.words[i] as u64) * (Q.words[j] as u64);

            acc = temp & 0xffffffff;
            for k in (0..(i + j + 2)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

            acc = temp >> 32;
            for k in (0..(i + j + 1)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

        }
    }

    acc = 0;

    for i in (8..16).rev() {
        acc = acc + (b512[i] as u64) + (buf[i] as u64);
        acc = acc >> 32;
    }

    for i in (0..8).rev() {
        acc = acc + (b512[i] as u64) + (buf[i] as u64);
        res.words[i] = acc as u32;
        acc = acc >> 32;
    }

    fp25519_uint_wrap_mod_order(acc, res);

}

unsafe fn fp25519_uint_ginc(res: *mut Fp25519Uint, val: *const Fp25519Uint) {
    let mut acc: u64 = 1;
    for i in (0..8).rev() {
        acc = acc + ((*val).words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
    fp25519_uint_wrap(acc, &mut (*res));
}

unsafe fn fp25519_uint_gdec(res: *mut Fp25519Uint, val: *const Fp25519Uint) {
    let mut acc: u64 = 0;
    for i in (0..8).rev() {
        acc = acc + ((*val).words[i] as u64) + (P_SUB1.words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
    fp25519_uint_wrap(acc, &mut (*res));
}

unsafe fn fp25519_uint_gadd(res: *mut Fp25519Uint, lhs: *const Fp25519Uint, rhs: *const Fp25519Uint) {
    let mut acc: u64 = 0;
    for i in (0..8).rev() {
        acc = acc + ((*lhs).words[i] as u64) + ((*rhs).words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
    fp25519_uint_wrap(acc, &mut (*res));
}

unsafe fn fp25519_uint_gsub(res: *mut Fp25519Uint, lhs: *const Fp25519Uint, rhs: *const Fp25519Uint) {
    let mut rhs_addinv: Fp25519Uint = Fp25519Uint::new();
    fp25519_uint_gaddinv(&mut rhs_addinv, &(*rhs));
    fp25519_uint_gadd(res, lhs, &rhs_addinv as *const Fp25519Uint);
}

unsafe fn fp25519_uint_gmul(res: *mut Fp25519Uint, lhs: *const Fp25519Uint, rhs: *const Fp25519Uint) {

    let mut buf: [u32; 16] = [0; 16];
    let mut acc: u64;

    for i in 0..8 {
        for j in 0..8 {

            let temp: u64 = ((*lhs).words[i] as u64) * ((*rhs).words[j] as u64);

            acc = temp & 0xffffffff;
            for k in (0..(i + j + 2)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

            acc = temp >> 32;
            for k in (0..(i + j + 1)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

        }
    }

    acc = ((!((((buf[8] >> 31) as u64) & 1).wrapping_sub(1))) & 19) as u64;
    buf[8] = buf[8] & 0x7fffffff;
    for i in (0..8).rev() {
        let temp: u64 = buf[i] as u64;
        acc = acc + (buf[i + 8] as u64) + (temp << 5) + (temp << 2) + (temp << 1);
        buf[i + 8] = acc as u32;
        acc = acc >> 32;
    }

    acc = (acc << 5) + (acc << 2) + (acc << 1);
    acc = acc + (((!((((buf[8] >> 31) as u64) & 1).wrapping_sub(1))) & 19) as u64);
    buf[8] = buf[8] & 0x7fffffff;
    for i in (0..8).rev() {
        acc = acc + (buf[i + 8] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }

    fp25519_uint_wrap(acc, &mut (*res));

}

unsafe fn fp25519_uint_gdiv(res: *mut Fp25519Uint, lhs: *const Fp25519Uint, rhs: *const Fp25519Uint) {
    let mut rhs_mulinv: Fp25519Uint = Fp25519Uint::new();
    fp25519_uint_gmulinv(&mut rhs_mulinv, &(*rhs));
    fp25519_uint_gmul(res, lhs, &rhs_mulinv as *const Fp25519Uint);
}

unsafe fn fp25519_uint_gpow(res: *mut Fp25519Uint, base: *const Fp25519Uint, exp: *const Fp25519Uint) {

    let mut a: Fp25519Uint = Fp25519Uint::from_usize(1);
    let mut b: Fp25519Uint = (*base).clone();
    let mut swap: bool = false;
    let mut j: usize = 31; // i == 0 ? j = 31 : 32;

    for i in 0..8 {

        while j > 0 {

            j = j - 1;

            let bit: bool = ((*exp).words[i] >> j) & 1 == 1;
            swap = swap ^ bit;
            Fp25519Uint::constant_time_swap(&mut a, &mut b, swap);
            swap = bit;

            Fp25519Uint::gmul_assign(&mut b, &a);
            Fp25519Uint::gsqr_assign(&mut a);

        }

        j = 32;

    }

    Fp25519Uint::constant_time_swap(&mut a, &mut b, swap);
    *res = a.clone();

}

unsafe fn fp25519_uint_gaddinv(res: *mut Fp25519Uint, val: *const Fp25519Uint) {
    let mut acc: u64 = 1;
    for i in (0..8).rev() {
        acc = acc + (((*val).words[i] as u64) ^ 0xffffffff) + (P.words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
}

unsafe fn fp25519_uint_gmulinv(res: *mut Fp25519Uint, val: *const Fp25519Uint) {
    fp25519_uint_gpow(res, val, &P_SUB2 as *const Fp25519Uint);
}

unsafe fn fp25519_uint_gadd_mod_order(res: *mut Fp25519Uint, lhs: *const Fp25519Uint,
    rhs: *const Fp25519Uint) {
    let mut acc: u64 = 0;
    for i in (0..8).rev() {
        acc = acc + ((*lhs).words[i] as u64) + ((*rhs).words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
    fp25519_uint_wrap_mod_order(acc, &mut (*res));
}

unsafe fn fp25519_uint_gmul_mod_order(res: *mut Fp25519Uint, lhs: *const Fp25519Uint,
    rhs: *const Fp25519Uint) {

    let mut buf: [u32; 16] = [0; 16];
    let mut acc: u64;

    for i in 0..8 {
        for j in 0..8 {

            let temp: u64 = ((*lhs).words[i] as u64) * ((*rhs).words[j] as u64);

            acc = temp & 0xffffffff;
            for k in (0..(i + j + 2)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

            acc = temp >> 32;
            for k in (0..(i + j + 1)).rev() {
                acc = acc + (buf[k] as u64);
                buf[k] = acc as u32;
                acc = acc >> 32;
            }

        }
    }

    Fp25519Uint::mod_order(&mut (*res), &buf[..]);

}

unsafe fn edwards25519_point_add(res: *mut Edwards25519Point, lhs: *const Edwards25519Point,
    rhs: *const Edwards25519Point) {

    let mut t1: Fp25519Uint = Fp25519Uint::new();
    let mut t2: Fp25519Uint = Fp25519Uint::new();
    let mut t3: Fp25519Uint = Fp25519Uint::new();
    let mut t4: Fp25519Uint = Fp25519Uint::new();
    let mut t5: Fp25519Uint = Fp25519Uint::new();

    // A  = (Y1 - X1) * (Y2 - X2)
    Fp25519Uint::gsub(&mut t5, &(*lhs).y, &(*lhs).x);
    Fp25519Uint::gsub(&mut t1, &(*rhs).y, &(*rhs).x);
    Fp25519Uint::gmul_assign(&mut t5, &t1);

    // B  = (Y1 + X1) * (Y2 + X2)
    Fp25519Uint::gadd(&mut t4, &(*lhs).y, &(*lhs).x);
    Fp25519Uint::gadd(&mut t1, &(*rhs).y, &(*rhs).x);
    Fp25519Uint::gmul_assign(&mut t4, &t1);

    // E  = B - A
    Fp25519Uint::gsub(&mut t1, &t4, &t5);

    // H  = B + A
    Fp25519Uint::gadd_assign(&mut t4, &t5);

    // C  = T1 * 2 * d * T2
    Fp25519Uint::gmul(&mut t5, &(*lhs).t, &(*rhs).t);
    Fp25519Uint::gmul_assign(&mut t5, &D2);

    // D  = Z1 * 2 * Z2
    Fp25519Uint::gdbl(&mut t3, &(*lhs).z);
    Fp25519Uint::gmul_assign(&mut t3, &(*rhs).z);

    // F  = D - C
    Fp25519Uint::gsub(&mut t2, &t3, &t5);

    // G  = D + C
    Fp25519Uint::gadd_assign(&mut t3, &t5);

    // X3 = E * F
    Fp25519Uint::gmul(&mut (*res).x, &t1, &t2);

    // Y3 = G * H
    Fp25519Uint::gmul(&mut (*res).y, &t3, &t4);

    // Z3 = F * G
    Fp25519Uint::gmul(&mut (*res).z, &t2, &t3);

    // T3 = E * H
    Fp25519Uint::gmul(&mut (*res).t, &t1, &t4);

}

unsafe fn edwards25519_point_scalar_mul(res: *mut Edwards25519Point, p: *const Edwards25519Point,
    s: &Fp25519Uint) {

    let mut a: Edwards25519Point = Edwards25519Point::new_neutral_point(); // (0, 1, 1, 0)
    let mut b: Edwards25519Point = (*p).clone();
    let mut swap: bool = false;
    let mut j: usize = 31; // i == 0 ? j = 31 : 32;

    for i in 0..8 {

        while j > 0 {

            j = j - 1;

            let bit: bool = (s.words[i] >> j) & 1 == 1;
            swap = swap ^ bit;
            Edwards25519Point::constant_time_swap(&mut a, &mut b, swap);
            swap = bit;

            Edwards25519Point::add_assign(&mut b, &a);
            Edwards25519Point::dbl_assign(&mut a);

        }

        j = 32;

    }

    Edwards25519Point::constant_time_swap(&mut a, &mut b, swap);
    *res = a.clone();

}