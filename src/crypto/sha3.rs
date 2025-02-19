use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::feature::BlockHash;
use crate::crypto::feature::Hash;
use crate::crypto::feature::Xof;

pub struct Sha3224 {
    state: Sha3State
}

pub struct Sha3256 {
    state: Sha3State
}

pub struct Sha3384 {
    state: Sha3State
}

pub struct Sha3512 {
    state: Sha3State
}

pub struct Shake128 {
    state: Sha3State
}

pub struct Shake256 {
    state: Sha3State
}

impl Sha3224 {

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Hash for Sha3224 {

    const MESSAGE_DIGEST_LEN: usize = SHA3_224_MESSAGE_DIGEST_LEN;

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_224_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_digest_oneshot(&mut a, msg, SHA3_224_RATE);

        for i in 0..4 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            if i >= 3 {
                break;
            }
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHA3_224_RATE);
        return Ok(self);
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_224_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_squeeze(&mut self.state, &mut a, SHA3_224_RATE);

        for i in 0..4 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            if i >= 3 {
                break;
            }
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

}

impl BlockHash for Sha3224 {
    const BLOCK_SIZE: usize = SHA3_224_RATE;
}

impl Sha3256 {

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Hash for Sha3256 {

    const MESSAGE_DIGEST_LEN: usize = SHA3_256_MESSAGE_DIGEST_LEN;

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_256_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_digest_oneshot(&mut a, msg, SHA3_256_RATE);

        for i in 0..4 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHA3_256_RATE);
        return Ok(self);
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_256_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_squeeze(&mut self.state, &mut a, SHA3_256_RATE);

        for i in 0..4 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

}

impl BlockHash for Sha3256 {
    const BLOCK_SIZE: usize = SHA3_256_RATE;
}

impl Sha3384 {

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Hash for Sha3384 {

    const MESSAGE_DIGEST_LEN: usize = SHA3_384_MESSAGE_DIGEST_LEN;

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_384_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_digest_oneshot(&mut a, msg, SHA3_384_RATE);

        for i in 0..6 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHA3_384_RATE);
        return Ok(self);
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_384_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_squeeze(&mut self.state, &mut a, SHA3_384_RATE);

        for i in 0..6 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

}

impl BlockHash for Sha3384 {
    const BLOCK_SIZE: usize = SHA3_384_RATE;
}

impl Sha3512 {

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Hash for Sha3512 {

    const MESSAGE_DIGEST_LEN: usize = SHA3_512_MESSAGE_DIGEST_LEN;

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_512_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_digest_oneshot(&mut a, msg, SHA3_512_RATE);

        for i in 0..8 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHA3_512_RATE);
        return Ok(self);
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {

        if md.len() != SHA3_512_MESSAGE_DIGEST_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut a: [u64; 25] = [0; 25];

        sha3_squeeze(&mut self.state, &mut a, SHA3_512_RATE);

        for i in 0..8 {
            let b: usize = i << 3;
            md[b + 0] = (a[i] >>  0) as u8;
            md[b + 1] = (a[i] >>  8) as u8;
            md[b + 2] = (a[i] >> 16) as u8;
            md[b + 3] = (a[i] >> 24) as u8;
            md[b + 4] = (a[i] >> 32) as u8;
            md[b + 5] = (a[i] >> 40) as u8;
            md[b + 6] = (a[i] >> 48) as u8;
            md[b + 7] = (a[i] >> 56) as u8;
        }

        return Ok(());

    }

}

impl BlockHash for Sha3512 {
    const BLOCK_SIZE: usize = SHA3_512_RATE;
}

impl Shake128 {

    pub const RATE: usize = SHAKE128_RATE;

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Xof for Shake128 {

    fn output_oneshot(msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return if output.len() != d {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            shake_output_oneshot(msg, output, d, SHAKE128_RATE);
            Ok(())
        }
    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHAKE128_RATE);
        return Ok(self);
    }

    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return if output.len() != d {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            shake_squeeze(&mut self.state, output, d, SHAKE128_RATE);
            Ok(())
        }
    }

}

impl Shake256 {

    pub const RATE: usize = SHAKE256_RATE;

    pub fn new() -> Self {
        return Self{
            state: Sha3State{
                a: [0; 25],
                buf: [0; 168],
                buf_len: 0
            }
        };
    }

}

impl Xof for Shake256 {

    fn output_oneshot(msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return if output.len() != d {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            shake_output_oneshot(msg, output, d, SHAKE256_RATE);
            Ok(())
        }
    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.state.a = [0; 25];
        self.state.buf_len = 0;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        sha3_absorb(&mut self.state, msg, SHAKE256_RATE);
        return Ok(self);
    }

    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return if output.len() != d {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            shake_squeeze(&mut self.state, output, d, SHAKE256_RATE);
            Ok(())
        }
    }

}

struct Sha3State {
    a: [u64; 25],
    buf: [u8; 168],
    buf_len: usize
}

static RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

const SHA3_224_MESSAGE_DIGEST_LEN: usize = 28;
const SHA3_256_MESSAGE_DIGEST_LEN: usize = 32;
const SHA3_384_MESSAGE_DIGEST_LEN: usize = 48;
const SHA3_512_MESSAGE_DIGEST_LEN: usize = 64;

const SHA3_224_RATE: usize = 144;
const SHA3_256_RATE: usize = 136;
const SHA3_384_RATE: usize = 104;
const SHA3_512_RATE: usize = 72;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

impl Drop for Sha3State {
    fn drop(&mut self) {
        self.a.fill(0);
        self.buf.fill(0);
        self.buf_len = 0;
    }
}

fn rotl64(u: u64, r: usize) -> u64 {
    return (u << r) | (u >> ((64 - r) & 63));
}

fn sha3_block(a: &mut [u64; 25]) {

    let mut b: [u64; 25] = [0; 25];
    let mut t: [u64; 25] = [0; 25];

    for r in 0..24 {

        // theta
        t[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        t[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        t[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        t[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        t[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        b[0] = t[4] ^ rotl64(t[1], 1);
        b[1] = t[0] ^ rotl64(t[2], 1);
        b[2] = t[1] ^ rotl64(t[3], 1);
        b[3] = t[2] ^ rotl64(t[4], 1);
        b[4] = t[3] ^ rotl64(t[0], 1);
        a[ 0] = a[ 0] ^ b[0];
        a[ 1] = a[ 1] ^ b[1];
        a[ 2] = a[ 2] ^ b[2];
        a[ 3] = a[ 3] ^ b[3];
        a[ 4] = a[ 4] ^ b[4];
        a[ 5] = a[ 5] ^ b[0];
        a[ 6] = a[ 6] ^ b[1];
        a[ 7] = a[ 7] ^ b[2];
        a[ 8] = a[ 8] ^ b[3];
        a[ 9] = a[ 9] ^ b[4];
        a[10] = a[10] ^ b[0];
        a[11] = a[11] ^ b[1];
        a[12] = a[12] ^ b[2];
        a[13] = a[13] ^ b[3];
        a[14] = a[14] ^ b[4];
        a[15] = a[15] ^ b[0];
        a[16] = a[16] ^ b[1];
        a[17] = a[17] ^ b[2];
        a[18] = a[18] ^ b[3];
        a[19] = a[19] ^ b[4];
        a[20] = a[20] ^ b[0];
        a[21] = a[21] ^ b[1];
        a[22] = a[22] ^ b[2];
        a[23] = a[23] ^ b[3];
        a[24] = a[24] ^ b[4];

        // rho
        t[ 0] = rotl64(a[ 0],  0);
        t[ 1] = rotl64(a[ 1],  1);
        t[ 2] = rotl64(a[ 2], 62);
        t[ 3] = rotl64(a[ 3], 28);
        t[ 4] = rotl64(a[ 4], 27);
        t[ 5] = rotl64(a[ 5], 36);
        t[ 6] = rotl64(a[ 6], 44);
        t[ 7] = rotl64(a[ 7],  6);
        t[ 8] = rotl64(a[ 8], 55);
        t[ 9] = rotl64(a[ 9], 20);
        t[10] = rotl64(a[10],  3);
        t[11] = rotl64(a[11], 10);
        t[12] = rotl64(a[12], 43);
        t[13] = rotl64(a[13], 25);
        t[14] = rotl64(a[14], 39);
        t[15] = rotl64(a[15], 41);
        t[16] = rotl64(a[16], 45);
        t[17] = rotl64(a[17], 15);
        t[18] = rotl64(a[18], 21);
        t[19] = rotl64(a[19],  8);
        t[20] = rotl64(a[20], 18);
        t[21] = rotl64(a[21],  2);
        t[22] = rotl64(a[22], 61);
        t[23] = rotl64(a[23], 56);
        t[24] = rotl64(a[24], 14);

        // pi
        b[ 0] = t[ 0];
        b[ 1] = t[ 6];
        b[ 2] = t[12];
        b[ 3] = t[18];
        b[ 4] = t[24];
        b[ 5] = t[ 3];
        b[ 6] = t[ 9];
        b[ 7] = t[10];
        b[ 8] = t[16];
        b[ 9] = t[22];
        b[10] = t[ 1];
        b[11] = t[ 7];
        b[12] = t[13];
        b[13] = t[19];
        b[14] = t[20];
        b[15] = t[ 4];
        b[16] = t[ 5];
        b[17] = t[11];
        b[18] = t[17];
        b[19] = t[23];
        b[20] = t[ 2];
        b[21] = t[ 8];
        b[22] = t[14];
        b[23] = t[15];
        b[24] = t[21];

        // chi
        a[ 0] = b[ 0] ^ ((!b[ 1]) & b[ 2]);
        a[ 1] = b[ 1] ^ ((!b[ 2]) & b[ 3]);
        a[ 2] = b[ 2] ^ ((!b[ 3]) & b[ 4]);
        a[ 3] = b[ 3] ^ ((!b[ 4]) & b[ 0]);
        a[ 4] = b[ 4] ^ ((!b[ 0]) & b[ 1]);
        a[ 5] = b[ 5] ^ ((!b[ 6]) & b[ 7]);
        a[ 6] = b[ 6] ^ ((!b[ 7]) & b[ 8]);
        a[ 7] = b[ 7] ^ ((!b[ 8]) & b[ 9]);
        a[ 8] = b[ 8] ^ ((!b[ 9]) & b[ 5]);
        a[ 9] = b[ 9] ^ ((!b[ 5]) & b[ 6]);
        a[10] = b[10] ^ ((!b[11]) & b[12]);
        a[11] = b[11] ^ ((!b[12]) & b[13]);
        a[12] = b[12] ^ ((!b[13]) & b[14]);
        a[13] = b[13] ^ ((!b[14]) & b[10]);
        a[14] = b[14] ^ ((!b[10]) & b[11]);
        a[15] = b[15] ^ ((!b[16]) & b[17]);
        a[16] = b[16] ^ ((!b[17]) & b[18]);
        a[17] = b[17] ^ ((!b[18]) & b[19]);
        a[18] = b[18] ^ ((!b[19]) & b[15]);
        a[19] = b[19] ^ ((!b[15]) & b[16]);
        a[20] = b[20] ^ ((!b[21]) & b[22]);
        a[21] = b[21] ^ ((!b[22]) & b[23]);
        a[22] = b[22] ^ ((!b[23]) & b[24]);
        a[23] = b[23] ^ ((!b[24]) & b[20]);
        a[24] = b[24] ^ ((!b[20]) & b[21]);

        // iota
        a[0]  = a[0] ^ RC[r];

    }

}

fn sha3_digest_oneshot(a: &mut [u64; 25], msg: &[u8], rate: usize) {

    let mut b: usize = 0;
    let l: usize = msg.len();
    let r: usize = rate >> 3;

    for i in 0..25 {
        a[i] = 0;
    }

    while l - b >= rate {

        for i in 0..r {
            a[i] = a[i] ^ (
                 (msg[b + 0] as u64)        |
                ((msg[b + 1] as u64) <<  8) |
                ((msg[b + 2] as u64) << 16) |
                ((msg[b + 3] as u64) << 24) |
                ((msg[b + 4] as u64) << 32) |
                ((msg[b + 5] as u64) << 40) |
                ((msg[b + 6] as u64) << 48) |
                ((msg[b + 7] as u64) << 56)
            );
            b = b + 8;
        }

        sha3_block(a);

    }

    let mut i: usize = 0;
    let mut n: usize = 0;
    while b < l {
        a[i] = a[i] ^ ((msg[b] as u64) << n);
        n = n + 8;
        if n == 64 {
            n = 0;
            i = i + 1;
        }
        b = b + 1;
    }

    a[i]     = a[i]     ^ (0x06u64 << n);
    a[r - 1] = a[r - 1] ^ (0x80u64 << 56);

    sha3_block(a);

}

fn shake_output_oneshot(msg: &[u8], output: &mut [u8], d: usize, rate: usize) {

    let mut a: [u64; 25] = [0; 25];
    let mut b: usize = 0;
    let l: usize = msg.len();
    let r: usize = rate >> 3;

    while l - b >= rate {

        for i in 0..r {
            a[i] = a[i] ^ (
                 (msg[b + 0] as u64)        |
                ((msg[b + 1] as u64) <<  8) |
                ((msg[b + 2] as u64) << 16) |
                ((msg[b + 3] as u64) << 24) |
                ((msg[b + 4] as u64) << 32) |
                ((msg[b + 5] as u64) << 40) |
                ((msg[b + 6] as u64) << 48) |
                ((msg[b + 7] as u64) << 56)
            );
            b = b + 8;
        }

        sha3_block(&mut a);

    }

    let mut i: usize = 0;
    let mut n: usize = 0;
    while b < l {
        a[i] = a[i] ^ ((msg[b] as u64) << n);
        n = n + 8;
        if n == 64 {
            n = 0;
            i = i + 1;
        }
        b = b + 1;
    }

    a[i]     = a[i]     ^ (0x1fu64 << n);
    a[r - 1] = a[r - 1] ^ (0x80u64 << 56);

    b = 0;
    while b < d {

        sha3_block(&mut a);

        i = 0;
        n = 0;
        while b < d && i < r {
            output[b] = (a[i] >> n) as u8;
            n = n + 8;
            if n >= 64 {
                n = 0;
                i = i + 1;
            }
            b = b + 1;
        }

    }

}

fn sha3_absorb(state: &mut Sha3State, msg: &[u8], rate: usize) {

    let mut b: usize = if state.buf_len == 0 { 0 } else { rate - state.buf_len };
    let l: usize = msg.len();
    let r: usize = rate >> 3;

    if l < rate - state.buf_len {
        state.buf[state.buf_len..(state.buf_len + l)].copy_from_slice(&msg[..]);
        state.buf_len = state.buf_len + l;
        return;
    }

    if b != 0 {

        state.buf[state.buf_len..(state.buf_len + b)].copy_from_slice(&msg[..b]);

        for i in (0..rate).step_by(8) {
            state.a[i >> 3] = state.a[i >> 3] ^ (
                 (state.buf[i + 0] as u64)        |
                ((state.buf[i + 1] as u64) <<  8) |
                ((state.buf[i + 2] as u64) << 16) |
                ((state.buf[i + 3] as u64) << 24) |
                ((state.buf[i + 4] as u64) << 32) |
                ((state.buf[i + 5] as u64) << 40) |
                ((state.buf[i + 6] as u64) << 48) |
                ((state.buf[i + 7] as u64) << 56)
            );
        }

        sha3_block(&mut state.a);

    }

    while l - b >= rate {

        for i in 0..r {
            state.a[i] = state.a[i] ^ (
                 (msg[b + 0] as u64)        |
                ((msg[b + 1] as u64) <<  8) |
                ((msg[b + 2] as u64) << 16) |
                ((msg[b + 3] as u64) << 24) |
                ((msg[b + 4] as u64) << 32) |
                ((msg[b + 5] as u64) << 40) |
                ((msg[b + 6] as u64) << 48) |
                ((msg[b + 7] as u64) << 56)
            );
            b = b + 8;
        }

        sha3_block(&mut state.a);

    }

    if b < l {
        state.buf_len = l - b;
        state.buf[..state.buf_len].copy_from_slice(&msg[b..(b + state.buf_len)]);
    } else {
        state.buf_len = 0;
    }

}

fn sha3_squeeze(state: &Sha3State, a: &mut [u64; 25], rate: usize) {

    for i in 0..25 {
        a[i] = state.a[i];
    }

    let mut i: usize = 0;
    let mut n: usize = 0;
    let r: usize = rate >> 3;

    for b in 0..state.buf_len {
        a[i] = a[i] ^ ((state.buf[b] as u64) << n);
        n = n + 8;
        if n == 64 {
            n = 0;
            i = i + 1;
        }
    }

    a[i]     = a[i]     ^ (0x06u64 << n);
    a[r - 1] = a[r - 1] ^ (0x80u64 << 56);

    sha3_block(a);

}

fn shake_squeeze(state: &Sha3State, output: &mut [u8], d: usize, rate: usize) {

    let mut a: [u64; 25] = [0; 25];
    let mut i: usize = 0;
    let mut n: usize = 0;
    let r: usize = rate >> 3;

    for i in 0..25 {
        a[i] = state.a[i];
    }

    for b in 0..state.buf_len {
        a[i] = a[i] ^ ((state.buf[b] as u64) << n);
        n = n + 8;
        if n == 64 {
            n = 0;
            i = i + 1;
        }
    }

    a[i]     = a[i]     ^ (0x1fu64 << n);
    a[r - 1] = a[r - 1] ^ (0x80u64 << 56);

    let mut b = 0;
    while b < d {

        sha3_block(&mut a);

        i = 0;
        n = 0;
        while b < d && i < r {
            output[b] = (a[i] >> n) as u8;
            n = n + 8;
            if n >= 64 {
                n = 0;
                i = i + 1;
            }
            b = b + 1;
        }

    }

}