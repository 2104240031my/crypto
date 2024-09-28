use crate::crypto::CryptoError;

pub struct Curve25519Point {
    x: Curve25519Uint,
    y: Curve25519Uint,
    z: Curve25519Uint,
    t: Curve25519Uint
}

pub struct Curve25519Uint {
    w: Uint256
}

// (2 ^ 255) - 19
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
const P: Curve25519Uint = Curve25519Uint{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
]};

// (2 ^ 256) - P
// 0x8000000000000000000000000000000000000000000000000000000000000013
const P_ADDINV: Curve25519Uint = Curve25519Uint{ w: [
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
]};

// ((2 ^ 255) - 19) - 2
// 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
const P_SUB_2: Curve25519Uint = Curve25519Uint{ w: [
    0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
]};

// 9
// 0x0000000000000000000000000000000000000000000000000000000000000009
const U: Curve25519Uint = Curve25519Uint{ w: [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009
]};

// -(121665 / 121666) == P - ((121665 * mulinv(121666)) % P)
// 37095705934669439343138083508754565189542113879843219016388785533085940283555
// 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
const D: Curve25519Uint = Curve25519Uint{ w: [
    0x52036cee, 0x2b6ffe73, 0x8cc74079, 0x7779e898, 0x00700a4d, 0x4141d8ab, 0x75eb4dca, 0x135978a3
]};

// 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
const D2: Curve25519Uint = Curve25519Uint{ w: [
    0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
]};

// 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
const D2: Curve25519Uint = Curve25519Uint{ w: [
    0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
]};

// (2 ** 252) + 27742317777372353535851937790883648493
// 7237005577332262213973186563042994240857116359379907606001950938285454250989
// 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
const L: Curve25519Uint = Curve25519Uint{ w: [
    0x10000000, 0x00000000, 0x00000000, 0x000000001, 0x4def9de, 0xa2f79cd6, 0x5812631a, 0x5cf5d3ed
]};

// (2 ** 256) - L
// 0xefffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c13
const L_ADDINV: Curve25519Uint = Curve25519Uint{ w: [
    0xefffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xeb210621, 0x5d086329, 0xa7ed9ce5, 0xa30a2c13
]};

// 71336056475231800826343715077027849978041630819377026201054086228062141447707
// 0x9db6c6f26fe9183614e75438ffa36beab1a206f2fdba84ffd2b51da312547e1b
const NDASH: Curve25519Uint = Curve25519Uint{ w: [
    0x9db6c6f2, 0x6fe91836, 0x14e75438, 0xffa36bea, 0xb1a206f2, 0xfdba84ff, 0xd2b51da3, 0x12547e1b
]};

// 1627715501170711445284395025044413883736156588369414752970002579683115011841
// 0x0399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f01
const RR: Curve25519Uint = Curve25519Uint{ w: [
    0x0399411b, 0x7c309a3d, 0xceec73d2, 0x17f5be65, 0xd00e1ba7, 0x68859347, 0xa40611e3, 0x449c0f01
]};

const B: Curve25519Point = Curve25519Point{

    // 15112221349535400772501151409588531511454012693041857206046113283949847762202
    // 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    x: Curve25519Uint{ w: [
        0x216936d3, 0xcd6e53fe, 0xc0a4e231, 0xfdd6dc5c, 0x692cc760, 0x9525a7b2, 0xc9562d60, 0x8f25d51a
    ]},

    // 46316835694926478169428394003475163141307993866256225615783033603165251855960
    // 0x6666666666666666666666666666666666666666666666666666666666666658
    y: Curve25519Uint{ w: [
        0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666658
    ]},

    // 1
    // 0x0000000000000000000000000000000000000000000000000000000000000001
    z: Curve25519Uint{ w: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
    ]},

    // 46827403850823179245072216630277197565144205554125654976674165829533817101731
    // 0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3
    t: Curve25519Uint{ w: [
        0x67875f0f, 0xd78b7665, 0x66ea4e8e, 0x64abe37d, 0x20f09f80, 0x775152f5, 0x6dde8ab3, 0xa5b7dda3
    ]}

};


impl Curve25519Point {

    // t = (x * y) / z

    fn constant_time_swap(a: &mut Self, b: &mut Self, swap: bool) {
        Curve25519Uint::constant_time_swap(&mut a.x, &mut b.x, swap);
        Curve25519Uint::constant_time_swap(&mut a.y, &mut b.y, swap);
        Curve25519Uint::constant_time_swap(&mut a.z, &mut b.z, swap);
        Curve25519Uint::constant_time_swap(&mut a.t, &mut b.t, swap);
    }

    pub fn scalar_mul(q: &mut Curve25519Point, p: &Curve25519Point, s: &Curve25519Uint) {

        let mut r0: Self = Curve25519Point{};
        let mut r1: Self = p.clone();

        let mut swap: usize = 0;
        let mut bit: usize;

        let mut j: usize = 31; // i == 0 ? j = 31 : 32;

        for i in 0..8 {

            while j > 0 {
                j = j - 1;
                bit = ((s.w[i] as usize) >> j) & 1;
                // [*5] section-3.1 Fig. 3., [*6] pp5
                if bit == 0 {
                    Self::add(&mut r1, &r0, &r1);
                    Self::dbl(&mut r0, &r0);
                } else {
                    Self::add(&mut r0, &r0, &r1);
                    Self::dbl(&mut r1, &r1);
                }
                // Self::constant_time_swap(&mut r0, &mut r1, swap == 1);
                // Self::add(&mut r1, &r0, &r1);
                // Self::dbl(&mut r0, &r0);
            }

            j = 32;

        }

        return r0;

    }

    pub fn add(v: &mut Curve25519Point, lhs: &Curve25519Point, rhs: &Curve25519Point) {

        let mut t1: Curve25519Uint = Curve25519Uint::new();
        let mut t2: Curve25519Uint = Curve25519Uint::new();
        let mut t3: Curve25519Uint = Curve25519Uint::new();
        let mut t4: Curve25519Uint = Curve25519Uint::new();
        let mut t5: Curve25519Uint = Curve25519Uint::new();

        // A = (Y1-X1)*(Y2-X2)
        Curve25519Uint::gsub(&mut t5, &lhs.y, &lhs.x);
        Curve25519Uint::gsub(&mut t1, &rhs.y, &rhs.x);
        Curve25519Uint::gmul_assign(&mut t5, &t2);

        // B = (Y1+X1)*(Y2+X2)
        Curve25519Uint::gadd(&mut t4, &lhs.y, &lhs.x);
        Curve25519Uint::gadd(&mut t1, &rhs.y, &rhs.x);
        Curve25519Uint::gmul_assign(&mut t4, &t1);

        // E = B-A
        Curve25519Uint::gsub(&mut t1, &t4, &t5);

        // H = B+A
        Curve25519Uint::gadd_assign(&mut t4, &t5);

        // C = T1*2*d*T2
        Curve25519Uint::gmul(&mut t5, &lhs.t, &rhs.t);
        Curve25519Uint::gmul_assign(&mut t5, &Curve25519Uint::new_as(2));
        Curve25519Uint::gmul_assign(&mut t5, &D);

        // D = Z1*2*Z2
        Curve25519Uint::gmul(&mut t3, &lhs.z, &rhs.z);
        Curve25519Uint::gmul_assign(&mut t3, &Curve25519Uint::new_as(2));

        // F = D-C
        Curve25519Uint::gsub(&mut t2, &t3, &t5);

        // G = D+C
        Curve25519Uint::gadd_assign(&mut t3, &t5);

        // X3 = E*F
        Curve25519Uint::gmul(&mut v.x, &t1, &t2);

        // Y3 = G*H
        Curve25519Uint::gmul(&mut v.y, &t3, &t4);

        // Z3 = F*G
        Curve25519Uint::gmul(&mut v.z, &t2, &t3);

        // T3 = E*H
        Curve25519Uint::gmul(&mut v.t, &t1, &t4);

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

    pub fn dbl(v: &mut Curve25519Point, p: &Curve25519Point) {

        let mut t1: Curve25519Uint = Curve25519Uint::new();
        let mut t2: Curve25519Uint = Curve25519Uint::new();
        let mut t3: Curve25519Uint = Curve25519Uint::new();
        let mut t4: Curve25519Uint = Curve25519Uint::new();

        // A = X1^2
        Curve25519Uint::gsqr(&mut t1, &p.x);

        // B = Y1^2
        Curve25519Uint::gsqr(&mut t3, &p.y);

        // C = 2*Z1^2
        Curve25519Uint::gsqr(&mut t2, &p.z);
        Curve25519Uint::gmul_assign(&mut t2, &Curve25519Uint::new_as(2));

        // H = A+B
        Curve25519Uint::gadd(&mut t4, &t1, &t3);

        // G = A-B
        Curve25519Uint::gsub_assign(&mut t3, &t1);

        // F = C+G
        Curve25519Uint::gsub_assign(&mut t2, &t3);

        // E = H-(X1+Y1)^2
        Curve25519Uint::gadd(&mut t1, &p.x, &p.y);
        Curve25519Uint::gsqr_assign(&mut t1);
        Curve25519Uint::gsub_assign(&mut t1, &t4);

        // X3 = E*F
        Curve25519Uint::gmul_assign(&mut v.x, &t1, &t2);

        // Y3 = G*H
        Curve25519Uint::gmul_assign(&mut v.y, &t3, &t4);

        // Z3 = F*G
        Curve25519Uint::gmul_assign(&mut v.z, &t2, &t3);

        // T3 = E*H
        Curve25519Uint::gmul_assign(&mut v.t, &t1, &t4);

        // A = X1^2
        // B = Y1^2
        // C = 2*Z1^2
        // H = A+B
        // E = H-(X1+Y1)^2
        // G = A-B
        // F = C+G
        // X3 = E*F
        // Y3 = G*H
        // T3 = E*H
        // Z3 = F*G

    }

}



impl Curve25519Uint {

    pub fn new() -> Self {
        return Self{ w: [0; 8] };
    }

    pub fn new_as(u: usize) -> Self {
        return Self{ w: [0, 0, 0, 0, 0, 0, (u >> 32) as u32, (u & 0xffffffffusize) as u32] };
    }

    pub fn new_as_u_coordinate_of_base_point(u: usize) -> Self {
        return Self{ w: [] };
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
        Self::reduc_once(&mut v);
        return Ok(v);
    }

    pub fn try_into_bytes(&self, b: &mut [u8]) -> Option<CryptoError> {

        if b.len() < 32 {
            return Some(CryptoError::new("the length of bytes \"b\" is not enough"));
        }

        for i in 0..8 {
            let j: usize = i << 2;
            b[j + 0] = (self.w[7 - i] >>  0) as u8;
            b[j + 1] = (self.w[7 - i] >>  8) as u8;
            b[j + 2] = (self.w[7 - i] >> 16) as u8;
            b[j + 3] = (self.w[7 - i] >> 24) as u8;
        }

        return None;

    }

    pub fn constant_time_swap(a: &mut Self, b: &mut Self, swap: bool) {
        let mask: u32 = if swap { u32::MAX } else { 0 }
        for i in 0..8 {
            let x: u32 = (a.w[i] ^ b.w[i]) & mask;
            a.w[i] = a.w[i] ^ x;
            b.w[i] = b.w[i] ^ x;
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

        let mut bit: u64 = 1; // current bit
        let mut l: u64   = 0; // summary of left
        let mut r: u64   = 0; // summary of right

        for i in (0..8).rev() {
            let gt_mask: u64 = if lhs.w[i] > rhs.w[i] { u64::MAX } else { 0u64 };
            let lt_mask: u64 = if lhs.w[i] < rhs.w[i] { u64::MAX } else { 0u64 };
            l = l ^ (bit & gt_mask);
            r = r ^ (bit & lt_mask);
            bit = bit << 1;
        }

        return l < r;

    }

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

    // res = res - if res < p { 0 } else { p }
    pub fn reduc_once(res: &mut Self) {
        let mask: u32 = if Uint256::lt(&res.w, &P) { 0u32 } else { u32::MAX };
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + (res.w[i] as u64) + ((P_ADDINV.w[i] & mask) as u64);
            res.w[i] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }
    }

    fn addinv(res: &mut Self, val: &Self) {
        let mut acc: u64 = 1;
        for i in (0..8).rev() {
            acc = acc + ((!(val.w[i] as u64)) & 0xffffffff) + (P.w[i] as u64);
            res.w[i] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }
    }

    fn mulinv(res: &mut Self, val: &Self) {
        Self::gpow(val, &P_SUB_2);
    }

    fn try_from_bytes_inner(b: &[u8]) -> Result<Self, CryptoError> {

        if b.len() < 32 {
            return Err(CryptoError::new("the length of bytes \"b\" is not enough"));
        }

        return Ok(Self{ w: [
            u32::from_le_bytes(b[28..32].try_into().unwrap()),
            u32::from_le_bytes(b[24..28].try_into().unwrap()),
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
            u32::from_le_bytes(b[16..20].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
            u32::from_le_bytes(b[8..12].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            u32::from_le_bytes(b[0..4].try_into().unwrap())
        ]});

    }

    unsafe fn gadd_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + ((*lhs).w[i] as u64) + ((*rhs).w[i] as u64);
            (*res).w[i] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
        }
        Self::reduc_once(&mut (*res));
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
            (*res).buf.w[i] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }

        Self::reduc_once(&mut (*res));

    }

    unsafe fn gdiv_inner(res: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut rhs_mulinv: Self = Self::new();
        Self::mulinv(&mut rhs_mulinv, &(*rhs));
        Self::add_inner(res, lhs, &rhs_mulinv as *const Self);
        Self::reduc_once(&mut (*res));
    }

    unsafe fn gpow_inner(res: *mut Self, base: *const Self, exp: *const Self) {

        let mut a: Self = Self::new_as(1);
        let mut b: Self = (*base).clone();

        for i in 0..8 {
            let mut s: u32 = 0x80000000;
            loop {

                if ((*exp).buf.w[i] & s) == 0 {
                    Self::gmul_assign(&mut b, &a);
                    Self::gsqr_assign(&mut a);
                } else {
                    Self::gmul_assign(&mut a, &b);
                    Self::gsqr_assign(&mut b);
                }

                s = s >> 1;

                if s == 0 {
                    break;
                }

            }
        }

        for i in 0..8 {
            (*res).w[i] = a.w[i];
        }

    }

}