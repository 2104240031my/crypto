use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;

pub struct Edwards25519Point {
    pub x: Ec25519Uint,
    pub y: Ec25519Uint,
    pub z: Ec25519Uint,
    pub t: Ec25519Uint
}

pub struct Ec25519Uint {
    pub w: [u32; 8]
}

// (2 ** 255) - 19
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
pub const P: Ec25519Uint = Ec25519Uint{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
]};

// (2 ** 256) - P
// 0x8000000000000000000000000000000000000000000000000000000000000013
const P_ADDINV: Ec25519Uint = Ec25519Uint{ w: [
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
]};

// ((2 ** 255) - 19) - 1
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
const P_SUB1: Ec25519Uint = Ec25519Uint{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffec
]};

// ((2 ** 255) - 19) - 2
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
const P_SUB2: Ec25519Uint = Ec25519Uint{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
]};

// (2 ** 252) + 27742317777372353535851937790883648493
// 7237005577332262213973186563042994240857116359379907606001950938285454250989
// 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
const L: Ec25519Uint = Ec25519Uint{ w: [
    0x10000000, 0x00000000, 0x00000000, 0x000000001, 0x4def9de, 0xa2f79cd6, 0x5812631a, 0x5cf5d3ed
]};

// (2 ** 256) - L
// 0xefffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c13
const L_ADDINV: Ec25519Uint = Ec25519Uint{ w: [
    0xefffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xeb210621, 0x5d086329, 0xa7ed9ce5, 0xa30a2c13
]};

// 71336056475231800826343715077027849978041630819377026201054086228062141447707
// 0x9db6c6f26fe9183614e75438ffa36beab1a206f2fdba84ffd2b51da312547e1b
const ND: Ec25519Uint = Ec25519Uint{ w: [
    0x9db6c6f2, 0x6fe91836, 0x14e75438, 0xffa36bea, 0xb1a206f2, 0xfdba84ff, 0xd2b51da3, 0x12547e1b
]};

// 1627715501170711445284395025044413883736156588369414752970002579683115011841
// 0x0399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f01
const RR: Ec25519Uint = Ec25519Uint{ w: [
    0x0399411b, 0x7c309a3d, 0xceec73d2, 0x17f5be65, 0xd00e1ba7, 0x68859347, 0xa40611e3, 0x449c0f01
]};

// (486662 - 2) / 4 == 121665
// 0x000000000000000000000000000000000000000000000000000000000001db41
pub const A24: Ec25519Uint = Ec25519Uint{ w: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0001db41
]};

// 9
// 0x0000000000000000000000000000000000000000000000000000000000000009
pub const U: Ec25519Uint = Ec25519Uint{ w: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009
]};

// -(121665 / 121666) == P - ((121665 * mulinv(121666)) % P)
// 37095705934669439343138083508754565189542113879843219016388785533085940283555
// 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
pub const D: Ec25519Uint = Ec25519Uint{ w: [
    0x52036cee, 0x2b6ffe73, 0x8cc74079, 0x7779e898, 0x00700a4d, 0x4141d8ab, 0x75eb4dca, 0x135978a3
]};

// 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
const D2: Ec25519Uint = Ec25519Uint{ w: [
    0x2406d9dc, 0x56dffce7, 0x198e80f2, 0xeef3d130, 0x00e0149a, 0x8283b156, 0xebd69b94, 0x26b2f159
]};

pub const B: Edwards25519Point = Edwards25519Point{

    // 15112221349535400772501151409588531511454012693041857206046113283949847762202
    // 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    x: Ec25519Uint{ w: [
        0x216936d3, 0xcd6e53fe, 0xc0a4e231, 0xfdd6dc5c, 0x692cc760, 0x9525a7b2, 0xc9562d60, 0x8f25d51a
    ]},

    // 46316835694926478169428394003475163141307993866256225615783033603165251855960
    // 0x6666666666666666666666666666666666666666666666666666666666666658
    y: Ec25519Uint{ w: [
        0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666658
    ]},

    // 1
    // 0x0000000000000000000000000000000000000000000000000000000000000001
    z: Ec25519Uint{ w: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    ]},

    // 46827403850823179245072216630277197565144205554125654976674165829533817101731
    // 0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3
    t: Ec25519Uint{ w: [
        0x67875f0f, 0xd78b7665, 0x66ea4e8e, 0x64abe37d, 0x20f09f80, 0x775152f5, 0x6dde8ab3, 0xa5b7dda3
    ]}

};

impl Edwards25519Point {

    pub fn new() -> Self {
        return Self{
            x: Ec25519Uint::new(),
            y: Ec25519Uint::new(),
            z: Ec25519Uint::new(),
            t: Ec25519Uint::new()
        };
    }

    pub fn new_neutral_point() -> Self {
        return Self{
            x: Ec25519Uint::from_usize(0),
            y: Ec25519Uint::from_usize(1),
            z: Ec25519Uint::from_usize(1),
            t: Ec25519Uint::from_usize(0)
        };
    }

    pub fn try_from_bytes() -> Self {
        return Self::new();
    }

    pub fn try_into_bytes() -> Self {
        return Self::new();
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
        Ec25519Uint::constant_time_swap(&mut a.x, &mut b.x, swap);
        Ec25519Uint::constant_time_swap(&mut a.y, &mut b.y, swap);
        Ec25519Uint::constant_time_swap(&mut a.z, &mut b.z, swap);
        Ec25519Uint::constant_time_swap(&mut a.t, &mut b.t, swap);
    }

    pub fn add(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::add_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn dbl(res: &mut Self, val: &Self) { unsafe {
        Self::add_inner(res as *mut Self, val as *const Self, val as *const Self);
    }}

    pub fn add_assign(res: &mut Self, rhs: &Self) { unsafe {
        Self::add_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    pub fn dbl_assign(res: &mut Self) { unsafe {
        Self::add_inner(res as *mut Self, res as *const Self, res as *const Self);
    }}

    pub fn scalar_mul(res: &mut Self, p: &Self, s: &Ec25519Uint) {

        let mut a: Self = Self::new_neutral_point(); // (0, 1, 1, 0)
        let mut b: Self = p.clone();
        let mut swap: bool = false;

        for i in 0..8 {
            for j in (0..32).rev() {

                let bit: bool = ((*s).w[i] >> j) & 1 == 1;
                swap = swap ^ bit;
                Self::constant_time_swap(&mut a, &mut b, swap);
                swap = bit;

                Self::add_assign(&mut b, &a);
                Self::dbl_assign(&mut a);

            }
        }

        Self::constant_time_swap(&mut a, &mut b, swap);
        *res = a.clone();

    }

    unsafe fn add_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {

        let mut t1: Ec25519Uint = Ec25519Uint::new();
        let mut t2: Ec25519Uint = Ec25519Uint::new();
        let mut t3: Ec25519Uint = Ec25519Uint::new();
        let mut t4: Ec25519Uint = Ec25519Uint::new();
        let mut t5: Ec25519Uint = Ec25519Uint::new();

        // A  = (Y1 - X1) * (Y2 - X2)
        Ec25519Uint::gsub(&mut t5, &(*lhs).y, &(*lhs).x);
        Ec25519Uint::gsub(&mut t1, &(*rhs).y, &(*rhs).x);
        Ec25519Uint::gmul_assign(&mut t5, &t2);

        // B  = (Y1 + X1) * (Y2 + X2)
        Ec25519Uint::gadd(&mut t4, &(*lhs).y, &(*lhs).x);
        Ec25519Uint::gadd(&mut t1, &(*rhs).y, &(*rhs).x);
        Ec25519Uint::gmul_assign(&mut t4, &t1);

        // E  = B - A
        Ec25519Uint::gsub(&mut t1, &t4, &t5);

        // H  = B + A
        Ec25519Uint::gadd_assign(&mut t4, &t5);

        // C  = T1 * 2 * d * T2
        Ec25519Uint::gmul(&mut t5, &(*lhs).t, &(*rhs).t);
        Ec25519Uint::gmul_assign(&mut t5, &D2);

        // D  = Z1 * 2 * Z2
        Ec25519Uint::gsqr(&mut t3, &(*lhs).z);
        Ec25519Uint::gmul_assign(&mut t3, &(*rhs).z);

        // F  = D - C
        Ec25519Uint::gsub(&mut t2, &t3, &t5);

        // G  = D + C
        Ec25519Uint::gadd_assign(&mut t3, &t5);

        // X3 = E * F
        Ec25519Uint::gmul(&mut (*res).x, &t1, &t2);

        // Y3 = G * H
        Ec25519Uint::gmul(&mut (*res).y, &t3, &t4);

        // Z3 = F * G
        Ec25519Uint::gmul(&mut (*res).z, &t2, &t3);

        // T3 = E * H
        Ec25519Uint::gmul(&mut (*res).t, &t1, &t4);

    }

}

impl Ec25519Uint {

    pub fn new() -> Self {
        return Self{ w: [0; 8] };
    }

    pub fn from_usize(u: usize) -> Self {
        return Self{ w: [0, 0, 0, 0, 0, 0, (u as u64 >> 32) as u32, u as u32] };
    }

    pub fn try_from_bytes_as_scalar(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes_inner(b)?;
        v.w[0] = v.w[0] & 0x7fffffff;
        v.w[0] = v.w[0] | 0x40000000;
        v.w[7] = v.w[7] & 0xfffffff8;
        return Ok(v);
    }

    pub fn try_from_bytes_as_u_coordinate(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes_inner(b)?;
        v.w[0] = v.w[0] & 0x7fffffff;
        Self::wrap(0, &mut v);
        return Ok(v);
    }

    pub fn try_into_bytes(&self, b: &mut [u8]) -> Option<CryptoError> {

        if b.len() < 32 {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        for i in (0..8).rev() {
            let j: usize = (7 - i) << 2;
            b[j + 0] = (self.w[i] >>  0) as u8;
            b[j + 1] = (self.w[i] >>  8) as u8;
            b[j + 2] = (self.w[i] >> 16) as u8;
            b[j + 3] = (self.w[i] >> 24) as u8;
        }

        return None;

    }

    pub fn clone(&self) -> Self {
        return Self{ w: [
            self.w[0],
            self.w[1],
            self.w[2],
            self.w[3],
            self.w[4],
            self.w[5],
            self.w[6],
            self.w[7]
        ]};
    }

    pub fn constant_time_swap(a: &mut Self, b: &mut Self, swap: bool) {
        let mask: u32 = if swap { u32::MAX } else { 0 };
        for i in 0..8 {
            let temp: u32 = (a.w[i] ^ b.w[i]) & mask;
            a.w[i] = a.w[i] ^ temp;
            b.w[i] = b.w[i] ^ temp;
        }
    }

    // lhs == rhs
    pub fn eq(lhs: &Self, rhs: &Self) -> bool {
        let mut acc: u64 = 0;
        for i in 0..8 {
            acc = acc | ((lhs.w[i] as u64) ^ (rhs.w[i] as u64));
        }
        return acc == 0;
    }

    // lhs < rhs
    pub fn lt(lhs: &Self, rhs: &Self) -> bool {
        return Self::lt_inner(0, lhs, 0, rhs);
    }

    // res = val + 1 mod p
    pub fn ginc(res: &mut Self, val: &Self) { unsafe {
        Self::ginc_inner(res as *mut Self, val as *const Self);
    }}

    // res = val - 1 mod p
    pub fn gdec(res: &mut Self, val: &Self) { unsafe {
        Self::gdec_inner(res as *mut Self, val as *const Self);
    }}

    // res = lhs + rhs mod p
    pub fn gadd(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gadd_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs - rhs mod p
    pub fn gsub(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gsub_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs * rhs mod p
    pub fn gmul(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gmul_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = val * val mod p
    pub fn gsqr(res: &mut Self, val: &Self) { unsafe {
        Self::gmul_inner(res as *mut Self, val as *const Self, val as *const Self);
    }}

    // res = lhs / rhs mod p
    pub fn gdiv(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gdiv_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = base ** exp mod p
    pub fn gpow(res: &mut Self, base: &Self, exp: &Self) { unsafe {
        Self::gpow_inner(res as *mut Self, base as *const Self, exp as *const Self);
    }}

    // res++ mod p
    pub fn ginc_assign(res: &mut Self) { unsafe {
        Self::ginc_inner(res as *mut Self, res as *const Self);
    }}

    // res-- mod p
    pub fn gdec_assign(res: &mut Self) { unsafe {
        Self::gdec_inner(res as *mut Self, res as *const Self);
    }}

    // res = res + rhs mod p
    pub fn gadd_assign(res: &mut Self, rhs: &Self) { unsafe {
        Self::gadd_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res - rhs mod p
    pub fn gsub_assign(res: &mut Self, rhs: &Self) { unsafe {
        Self::gsub_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * rhs mod p
    pub fn gmul_assign(res: &mut Self, rhs: &Self) { unsafe {
        Self::gmul_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * res mod p
    pub fn gsqr_assign(res: &mut Self) { unsafe {
        Self::gmul_inner(res as *mut Self, res as *const Self, res as *const Self);
    }}

    // res = res / rhs mod p
    pub fn gdiv_assign(res: &mut Self, rhs: &Self) { unsafe {
        Self::gdiv_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res ** exp mod p
    pub fn gpow_assign(res: &mut Self, exp: &Self) { unsafe {
        Self::gpow_inner(res as *mut Self, res as *const Self, exp as *const Self);
    }}

    // res = lhs + rhs mod l
    pub fn gadd_mod_order(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gadd_mod_order_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs * rhs mod l
    pub fn gmul_mod_order(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gmul_mod_order_inner(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = res + rhs mod l
    pub fn gadd_assign_mod_order(res: &mut Self, rhs: &Self) { unsafe {
        Self::gadd_mod_order_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * rhs mod l
    pub fn gmul_assign_mod_order(res: &mut Self, rhs: &Self) { unsafe {
        Self::gmul_mod_order_inner(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = b512 mod l
    pub fn mod_order(res: &mut Self, b512: &[u32]) { unsafe {

        let mut t: Self = Self::new();
        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;

        Self::mr(&mut t, b512);

        for i in 0..8 {
            for j in 0..8 {

                let temp: u64 = (t.w[i] as u64) * (RR.w[j] as u64);

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

        Self::mr(res, &buf[..]);

    }}

    fn try_from_bytes_inner(b: &[u8]) -> Result<Self, CryptoError> {

        if b.len() < 32 {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        return Ok(Self{ w: [
            u32::from_le_bytes(b[28..32].try_into().unwrap()),
            u32::from_le_bytes(b[24..28].try_into().unwrap()),
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
            u32::from_le_bytes(b[16..20].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
            u32::from_le_bytes(b[ 8..12].try_into().unwrap()),
            u32::from_le_bytes(b[ 4.. 8].try_into().unwrap()),
            u32::from_le_bytes(b[ 0.. 4].try_into().unwrap())
        ]});

    }

    fn lt_inner(lhs_carry: u64, lhs: &Self, rhs_carry: u64, rhs: &Self) -> bool {

        let mut bit: u64 = 1;
        let mut l: u64 = lhs_carry << 8; // summary of left
        let mut r: u64 = rhs_carry << 8; // summary of right

        for i in (0..8).rev() {
            let gt_mask: u64 = if lhs.w[i] > rhs.w[i] { u64::MAX } else { 0 };
            let lt_mask: u64 = if lhs.w[i] < rhs.w[i] { u64::MAX } else { 0 };
            l = l | (bit & gt_mask);
            r = r | (bit & lt_mask);
            bit = bit << 1;
        }

        return l < r;

    }

    // res = res - if res < p { 0 } else { p }
    fn wrap(res_carry: u64, res: &mut Self) {
        let mask: u32 = if Self::lt_inner(res_carry, &res, 0, &P) { 0 } else { u32::MAX };
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + (res.w[i] as u64) + ((P_ADDINV.w[i] & mask) as u64);
            res.w[i] = acc as u32;
            acc = acc >> 32;
        }
    }

    // res = res - if res < l { 0 } else { l }
    fn wrap_mod_order(res_carry: u64, res: &mut Self) {
        let mask: u32 = if Self::lt_inner(res_carry, &res, 0, &L) { 0 } else { u32::MAX };
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + (res.w[i] as u64) + ((L_ADDINV.w[i] & mask) as u64);
            res.w[i] = acc as u32;
            acc = acc >> 32;
        }
    }

    fn addinv(res: &mut Self, val: &Self) {
        let mut acc: u64 = 1;
        for i in (0..8).rev() {
            acc = acc + ((val.w[i] as u64) ^ 0xffffffff) + (P.w[i] as u64);
            res.w[i] = acc as u32;
            acc = acc >> 32;
        }
    }

    fn mulinv(res: &mut Self, val: &Self) {
        Self::gpow(res, val, &P_SUB2);
    }

    fn mr(res: &mut Self, b512: &[u32]) {

        let mut t: Self = Self::from_usize(0);
        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;

        for i in 0..8 {
            for j in 0..8 {

                let n: usize = i + j + 2;

                if n >= 8 {

                    let temp: u64 = (b512[i + 8] as u64) * (ND.w[j] as u64);

                    acc = temp & 0xffffffff;
                    for k in (0..(n - 8)).rev() {
                        acc = acc + (t.w[k] as u64);
                        t.w[k] = acc as u32;
                        acc = acc >> 32;
                    }

                    if n >= 9 {
                        acc = temp >> 32;
                        for k in (0..(n - 9)).rev() {
                            acc = acc + (t.w[k] as u64);
                            t.w[k] = acc as u32;
                            acc = acc >> 32;
                        }
                    }

                }

            }
        }

        for i in 0..8 {
            for j in 0..8 {

                let temp: u64 = (t.w[i] as u64) * (L.w[j] as u64);

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
            res.w[i] = acc as u32;
            acc = acc >> 32;
        }

        Self::wrap_mod_order(acc, res);

    }

    unsafe fn ginc_inner(res: *mut Self, val: *const Self) {
        let mut acc: u64 = 1;
        for i in (0..8).rev() {
            acc = acc + ((*val).w[i] as u64);
            (*res).w[i] = acc as u32;
            acc = acc >> 32;
        }
        Self::wrap(acc, &mut (*res));
    }

    unsafe fn gdec_inner(res: *mut Self, val: *const Self) {
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + ((*val).w[i] as u64) + (P_SUB1.w[i] as u64);
            (*res).w[i] = acc as u32;
            acc = acc >> 32;
        }
        Self::wrap(acc, &mut (*res));
    }

    unsafe fn gadd_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + ((*lhs).w[i] as u64) + ((*rhs).w[i] as u64);
            (*res).w[i] = acc as u32;
            acc = acc >> 32;
        }
        Self::wrap(acc, &mut (*res));
    }

    unsafe fn gsub_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut rhs_addinv: Self = Self::new();
        Self::addinv(&mut rhs_addinv, &(*rhs));
        Self::gadd_inner(res, lhs, &rhs_addinv as *const Self);
    }

    unsafe fn gmul_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {

        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;

        for i in 0..8 {
            for j in 0..8 {

                let temp: u64 = ((*lhs).w[i] as u64) * ((*rhs).w[j] as u64);

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
            (*res).w[i] = acc as u32;
            acc = acc >> 32;
        }

        Self::wrap(acc, &mut (*res));

    }

    unsafe fn gdiv_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut rhs_mulinv: Self = Self::new();
        Self::mulinv(&mut rhs_mulinv, &(*rhs));
        Self::gmul_inner(res, lhs, &rhs_mulinv as *const Self);
    }

    unsafe fn gpow_inner(res: *mut Self, base: *const Self, exp: *const Self) {

        let mut a: Self = Self::from_usize(1);
        let mut b: Self = (*base).clone();
        let mut swap: bool = false;

        for i in 0..8 {
            for j in (0..32).rev() {

                let bit: bool = ((*exp).w[i] >> j) & 1 == 1;
                swap = swap ^ bit;
                Ec25519Uint::constant_time_swap(&mut a, &mut b, swap);
                swap = bit;

                Ec25519Uint::gmul_assign(&mut b, &a);
                Ec25519Uint::gsqr_assign(&mut a);

            }
        }

        Ec25519Uint::constant_time_swap(&mut a, &mut b, swap);
        *res = a.clone();

    }

    unsafe fn gadd_mod_order_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + ((*lhs).w[i] as u64) + ((*rhs).w[i] as u64);
            (*res).w[i] = acc as u32;
            acc = acc >> 32;
        }
        Self::wrap_mod_order(acc, &mut (*res));
    }

    unsafe fn gmul_mod_order_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {

        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;

        for i in 0..8 {
            for j in 0..8 {

                let temp: u64 = ((*lhs).w[i] as u64) * ((*rhs).w[j] as u64);

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

        Self::mod_order(&mut (*res), &buf[..]);

    }

}
