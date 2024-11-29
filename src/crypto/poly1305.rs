use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::mac::MacStdFeature;
use crate::crypto::mac::MacStdConst;
use crate::crypto::mac::MacStdStaticFn;
use crate::crypto::mac::MacStdInstanceFn;

pub struct Poly1305 {
    key: Poly1305Key,
    acc: Poly1305Accumulator,
    buf: [u8; 16],
    buf_len: usize
}

impl Poly1305 {

    pub const KEY_LEN: usize = POLY1305_KEY_LEN;

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            key: Poly1305Key{
                r: Fp1305Uint::new(),
                s: Fp1305Uint::new()
            },
            acc: Poly1305Accumulator::new(),
            buf: [0; 16],
            buf_len: 0
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

    pub fn block(&mut self, block: &[u8]) -> Result<&mut Self, CryptoError> {
        return if block.len() != 16 {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            poly1305_block(&self.key, &mut self.acc, block);
            Ok(self)
        };
    }

    pub fn incomplete_block(&mut self, incomplete_block: &[u8]) -> Result<&mut Self, CryptoError> {
        return if incomplete_block.len() != 16 {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            poly1305_incomplete_block(&self.key, &mut self.acc, incomplete_block);
            Ok(self)
        };
    }

    pub fn mac(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {
        return if mac.len() != POLY1305_MAC_LEN {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            poly1305_mac(&self.key, &self.acc, mac);
            Ok(())
        };
    }

    pub fn block_unchecked(&mut self, block: &[u8]) -> &mut Self {
        poly1305_block(&self.key, &mut self.acc, block);
        return self;
    }

    pub fn incomplete_block_unchecked(&mut self, incomplete_block: &[u8]) -> &mut Self {
        poly1305_incomplete_block(&self.key, &mut self.acc, incomplete_block);
        return self;
    }

    pub fn mac_unchecked(&mut self, mac: &mut [u8]) {
        poly1305_mac(&self.key, &self.acc, mac);
    }

}

impl MacStdFeature for Poly1305 {}

impl MacStdConst for Poly1305 {
    const MAC_LEN: usize = POLY1305_MAC_LEN;
}

impl MacStdStaticFn for Poly1305 {

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

}

impl MacStdInstanceFn for Poly1305 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }
        self.key.r = Fp1305Uint::try_from_bytes_as_r(&key[0..16]).unwrap();
        self.key.s = Fp1305Uint::try_from_bytes(&key[16..32]).unwrap();
        return Ok(self);
    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.acc = Fp1305Uint::from_usize(0);
        self.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {

        let mut b: usize = if self.buf_len == 0 { 0 } else { 16 - self.buf_len };
        let l: usize = msg.len();

        if l < 16 - self.buf_len {
            self.buf[self.buf_len..(self.buf_len + l)].copy_from_slice(&msg[..]);
            self.buf_len = self.buf_len + l;
            return Ok(self);
        }

        if b != 0 {
            self.buf[self.buf_len..(self.buf_len + b)].copy_from_slice(&msg[..b]);
            poly1305_block(&self.key, &mut self.acc, &self.buf[..]);
        }

        while l - b >= 16 {
            poly1305_block(&self.key, &mut self.acc, &msg[b..(b + 16)]);
            b = b + 16;
        }

        if b < l {
            self.buf_len = l - b;
            self.buf[..self.buf_len].copy_from_slice(&msg[b..(b + self.buf_len)]);
        } else {
            self.buf_len = 0;
        }

        return Ok(self);

    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {

        if mac.len() != POLY1305_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        if self.buf_len != 0 {
            self.buf[self.buf_len] = 0x01;
            self.buf[(self.buf_len + 1)..].fill(0x00);
            let mut u: Fp1305Uint = Fp1305Uint::try_from_bytes(&self.buf[..]).unwrap();
            Fp1305Uint::gadd_assign(&mut u, &self.acc);
            Fp1305Uint::gmul_assign(&mut u, &self.key.r);
            Fp1305Uint::gadd_assign(&mut u, &self.key.s);
            u.try_into_bytes(mac).unwrap();
        } else {
            let mut u: Fp1305Uint = Fp1305Uint::new();
            Fp1305Uint::gadd(&mut u, &self.acc, &self.key.s);
            u.try_into_bytes(mac).unwrap();
        }

        return Ok(());

    }

}

struct Poly1305Key {
    r: Fp1305Uint,
    s: Fp1305Uint
}

type Poly1305Accumulator = Fp1305Uint;

fn poly1305_rekey(k: &mut Poly1305Key, key: &[u8]) {
    k.r = Fp1305Uint::try_from_bytes_as_r(&key[0..16]).unwrap();
    k.s = Fp1305Uint::try_from_bytes(&key[16..32]).unwrap();
}

fn poly1305_reset(a: &mut Poly1305Accumulator) {
    a.words[0] = 0;
    a.words[1] = 0;
    a.words[2] = 0;
    a.words[3] = 0;
    a.words[4] = 0;
}

fn poly1305_block(k: &Poly1305Key, a: &mut Poly1305Accumulator, block: &[u8]) {
    Fp1305Uint::gadd_assign(a, &Fp1305Uint::try_from_bytes_with_add_2_128(&block[..]).unwrap());
    Fp1305Uint::gmul_assign(a, &k.r);
}

fn poly1305_incomplete_block(k: &Poly1305Key, a: &mut Poly1305Accumulator, incomplete_block: &[u8]) {
    let mut block: [u8; 16] = [0; 16];
    block.copy_from_slice(incomplete_block);
    block[incomplete_block.len()] = 0x01;
    Fp1305Uint::gadd_assign(a, &Fp1305Uint::try_from_bytes(&block[..]).unwrap());
    Fp1305Uint::gmul_assign(a, &k.r);
}

fn poly1305_mac(k: &Poly1305Key, a: &Poly1305Accumulator, mac: &mut [u8]) {
    let mut u: Fp1305Uint = Fp1305Uint::new();
    Fp1305Uint::gadd(&mut u, a, &k.s);
    u.try_into_bytes(mac).unwrap();
}

struct Fp1305Uint {
    words: [u32; 5]
}

const POLY1305_KEY_LEN: usize = 32;
const POLY1305_MAC_LEN: usize = 16;

// (2 ** 130) - 5
// 1361129467683753853853498429727072845819
// 0x00000003fffffffffffffffffffffffffffffffb
const P: Fp1305Uint = Fp1305Uint{ words: [
    0x00000003, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffb
]};

// (2 ** 160) - p
const P_ADDINV: Fp1305Uint = Fp1305Uint{ words: [
    0xfffffffc, 0x00000000, 0x00000000, 0x00000000, 0x00000005
]};

impl Fp1305Uint {

    fn new() -> Self {
        return Self{ words: [0; 5] };
    }

    fn from_usize(u: usize) -> Self {
        return Self{ words: [0, 0, 0, (u as u64 >> 32) as u32, u as u32] };
    }

    fn from_u32_array(a: [u32; 5]) -> Self {
        return Self{ words: [a[0], a[1], a[2], a[3], a[4]] };
    }

    fn try_from_bytes(b: &[u8]) -> Result<Self, CryptoError> {

        if b.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        return Ok(Self{ words: [
            0x00000000,
            ((b[15] as u32) << 24) | ((b[14] as u32) << 16) | ((b[13] as u32) << 8) | (b[12] as u32),
            ((b[11] as u32) << 24) | ((b[10] as u32) << 16) | ((b[ 9] as u32) << 8) | (b[ 8] as u32),
            ((b[ 7] as u32) << 24) | ((b[ 6] as u32) << 16) | ((b[ 5] as u32) << 8) | (b[ 4] as u32),
            ((b[ 3] as u32) << 24) | ((b[ 2] as u32) << 16) | ((b[ 1] as u32) << 8) | (b[ 0] as u32)
        ]});

    }

    fn try_from_bytes_as_r(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes(b)?;
        v.words[1] = v.words[1] & 0x0ffffffc;
        v.words[2] = v.words[2] & 0x0ffffffc;
        v.words[3] = v.words[3] & 0x0ffffffc;
        v.words[4] = v.words[4] & 0x0fffffff;
        return Ok(v);
    }

    fn try_from_bytes_with_add_2_128(b: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self::try_from_bytes(b)?;
        v.words[0] = 0x00000001;
        return Ok(v);
    }

    fn try_into_bytes(&self, b: &mut [u8]) -> Result<(), CryptoError> {

        if b.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        for i in (1..5).rev() {
            let j: usize = (4 - i) << 2;
            b[j + 0] = (self.words[i] >>  0) as u8;
            b[j + 1] = (self.words[i] >>  8) as u8;
            b[j + 2] = (self.words[i] >> 16) as u8;
            b[j + 3] = (self.words[i] >> 24) as u8;
        }

        return Ok(());

    }

    // res = lhs + rhs mod p
    fn gadd(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp1305_uint_gadd(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = lhs * rhs mod p
    fn gmul(res: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        fp1305_uint_gmul(res as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    // res = res + rhs mod p
    fn gadd_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp1305_uint_gadd(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

    // res = res * rhs mod p
    fn gmul_assign(res: &mut Self, rhs: &Self) { unsafe {
        fp1305_uint_gmul(res as *mut Self, res as *const Self, rhs as *const Self);
    }}

}

fn fp1305_uint_lt(lhs_carry: u64, lhs: &Fp1305Uint, rhs_carry: u64, rhs: &Fp1305Uint) -> bool {

    let mut bit: u64 = 1;
    let mut l: u64 = lhs_carry << 5; // summary of left
    let mut r: u64 = rhs_carry << 5; // summary of right

    for i in (0..5).rev() {
        let gt_mask: u64 = if lhs.words[i] > rhs.words[i] { u64::MAX } else { 0 };
        let lt_mask: u64 = if lhs.words[i] < rhs.words[i] { u64::MAX } else { 0 };
        l = l | (bit & gt_mask);
        r = r | (bit & lt_mask);
        bit = bit << 1;
    }

    return l < r;

}

// res = res - if res < p { 0 } else { p }
fn fp1305_uint_wrap(res_carry: u64, res: &mut Fp1305Uint) {
    let mask: u32 = if fp1305_uint_lt(res_carry, &res, 0, &P) { 0 } else { u32::MAX };
    let mut acc: u64 = 0;
    for i in (0..5).rev() {
        acc = acc + (res.words[i] as u64) + ((P_ADDINV.words[i] & mask) as u64);
        res.words[i] = acc as u32;
        acc = acc >> 32;
    }
}

unsafe fn fp1305_uint_gadd(res: *mut Fp1305Uint, lhs: *const Fp1305Uint, rhs: *const Fp1305Uint) {
    let mut acc: u64 = 0;
    for i in (0..5).rev() {
        acc = acc + ((*lhs).words[i] as u64) + ((*rhs).words[i] as u64);
        (*res).words[i] = acc as u32;
        acc = acc >> 32;
    }
    fp1305_uint_wrap(acc, &mut (*res));
}

unsafe fn fp1305_uint_gmul(res: *mut Fp1305Uint, lhs: *const Fp1305Uint, rhs: *const Fp1305Uint) {

    let mut buf: [u32; 10] = [0; 10];
    let mut acc: u64;

    for i in 0..5 {
        for j in 0..5 {

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

    acc = 0;
    for i in (2..6).rev() {
        let temp: u64 = (((buf[i - 1] as u64) << 30) | ((buf[i] as u64) >> 2)) & 0xffffffff;
        acc = acc + (buf[i + 4] as u64) + (temp << 2) + temp;
        buf[i + 4] = acc as u32;
        acc = acc >> 32;
    }
    acc = acc + ((buf[5] as u64) & 3);
    buf[5] = (acc & 3) as u32;
    acc = (acc & (u64::MAX << 2)) + (acc >> 2);
    for i in (2..6).rev() {
        acc = acc + (buf[i + 4] as u64);
        (*res).words[i - 1] = acc as u32;
        acc = acc >> 32;
    }
    (*res).words[0] = ((acc + (buf[5] as u64)) & 3) as u32;

    fp1305_uint_wrap(0, &mut (*res));

}