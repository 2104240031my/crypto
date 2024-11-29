use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::stream_cipher::StreamCipherStdFeature;
use crate::crypto::stream_cipher::StreamCipherStdConst;
use crate::crypto::stream_cipher::StreamCipherStdInstanceFn;

pub struct ChaCha20 {
    state: ChaCha20State
}

impl ChaCha20 {

    pub fn new(key: &[u8], nonce: &[u8], counter: u32) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            state: ChaCha20State{
                words: [0; 16]
            }
        };
        v.reseed(key, nonce, counter)?;
        return Ok(v);
    }

    pub fn reseed(&mut self, key: &[u8], nonce: &[u8], counter: u32) -> Result<&mut Self, CryptoError> {
        self.rekey(key)?.reset(nonce, counter)?;
        return Ok(self);
    }

    pub fn reset(&mut self, nonce: &[u8], counter: u32) -> Result<&mut Self, CryptoError> {
        return if nonce.len() != 12 {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            chacha20_reset(&mut self.state, nonce, counter);
            Ok(self)
        };
    }

    pub fn block(&self, key_strm: &mut [u8]) -> Result<(), CryptoError> {

        if key_strm.len() != 64 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        chacha20_block(&self.state, key_strm);
        return Ok(());

    }

    pub fn block_unchecked(&self, key_strm: &mut [u8]) {
        chacha20_block(&self.state, key_strm);
    }

    pub fn set_counter(&mut self, ctr: u32) -> Result<(), CryptoError> {
        self.state.words[12] = ctr;
        return Ok(());
    }

    pub fn increment_counter(&mut self) -> Result<(), CryptoError> {
        self.state.words[12] = self.state.words[12] + 1;
        return Ok(());
    }

}

impl StreamCipherStdFeature for ChaCha20 {}

impl StreamCipherStdConst for ChaCha20  {
    const KEY_LEN: usize = CHACHA20_KEY_LEN;
}

impl StreamCipherStdInstanceFn for ChaCha20  {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if key.len() != 32 {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            chacha20_rekey(&mut self.state, key);
            Ok(self)
        };
    }

    fn encrypt_or_decrypt(&mut self, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);

        if len != outtext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut key_strm: [u8; 64] = [0; 64];

        for i in (0..n).step_by(64) {
            self.block_unchecked(&mut key_strm[..]);
            for j in i..(i + 64) {
                outtext[j] = intext[j] ^ key_strm[j - i];
            }
            self.increment_counter()?;
        }

        if n != len {
            self.block_unchecked(&mut key_strm[..]);
            for i in n..len {
                outtext[i] = intext[i] ^ key_strm[i - n];
            }
            self.increment_counter()?;
        }

        return Ok(());

    }

}

struct ChaCha20State {
    words: [u32; 16]
}

const CHACHA20_KEY_LEN: usize = 32;

const CHACHA20_CONST_W0: u32 = 0x61707865;
const CHACHA20_CONST_W1: u32 = 0x3320646e;
const CHACHA20_CONST_W2: u32 = 0x79622d32;
const CHACHA20_CONST_W3: u32 = 0x6b206574;

fn chacha20_rekey(s: &mut ChaCha20State, k: &[u8]) {
    s.words[4]  = ((k[ 3] as u32) << 24) | ((k[ 2] as u32) << 16) | ((k[ 1] as u32) << 8) | (k[ 0] as u32);
    s.words[5]  = ((k[ 7] as u32) << 24) | ((k[ 6] as u32) << 16) | ((k[ 5] as u32) << 8) | (k[ 4] as u32);
    s.words[6]  = ((k[11] as u32) << 24) | ((k[10] as u32) << 16) | ((k[ 9] as u32) << 8) | (k[ 8] as u32);
    s.words[7]  = ((k[15] as u32) << 24) | ((k[14] as u32) << 16) | ((k[13] as u32) << 8) | (k[12] as u32);
    s.words[8]  = ((k[19] as u32) << 24) | ((k[18] as u32) << 16) | ((k[17] as u32) << 8) | (k[16] as u32);
    s.words[9]  = ((k[23] as u32) << 24) | ((k[22] as u32) << 16) | ((k[21] as u32) << 8) | (k[20] as u32);
    s.words[10] = ((k[27] as u32) << 24) | ((k[26] as u32) << 16) | ((k[25] as u32) << 8) | (k[24] as u32);
    s.words[11] = ((k[31] as u32) << 24) | ((k[30] as u32) << 16) | ((k[29] as u32) << 8) | (k[28] as u32);
}

fn chacha20_reset(s: &mut ChaCha20State, n: &[u8], c: u32) {
    s.words[0]  = CHACHA20_CONST_W0;
    s.words[1]  = CHACHA20_CONST_W1;
    s.words[2]  = CHACHA20_CONST_W2;
    s.words[3]  = CHACHA20_CONST_W3;
    s.words[12] = c;
    s.words[13] = ((n[ 3] as u32) << 24) | ((n[ 2] as u32) << 16) | ((n[ 1] as u32) << 8) | (n[ 0] as u32);
    s.words[14] = ((n[ 7] as u32) << 24) | ((n[ 6] as u32) << 16) | ((n[ 5] as u32) << 8) | (n[ 4] as u32);
    s.words[15] = ((n[11] as u32) << 24) | ((n[10] as u32) << 16) | ((n[ 9] as u32) << 8) | (n[ 8] as u32);
}

fn chacha20_block(s: &ChaCha20State, k: &mut [u8]) {

    let mut r: ChaCha20State = ChaCha20State{ words: [
        s.words[ 0], s.words[ 1], s.words[ 2], s.words[ 3],
        s.words[ 4], s.words[ 5], s.words[ 6], s.words[ 7],
        s.words[ 8], s.words[ 9], s.words[10], s.words[11],
        s.words[12], s.words[13], s.words[14], s.words[15]
    ]};

    for _ in 0..10 {

        r.words[ 0] = r.words[ 0].wrapping_add(r.words[ 4]);
        r.words[12] = r.words[12] ^ r.words[ 0];
        r.words[12] = r.words[12].wrapping_shl(16) | (r.words[12] >> 16);
        r.words[ 8] = r.words[ 8].wrapping_add(r.words[12]);
        r.words[ 4] = r.words[ 4] ^ r.words[ 8];
        r.words[ 4] = r.words[ 4].wrapping_shl(12) | (r.words[ 4] >> 20);
        r.words[ 0] = r.words[ 0].wrapping_add(r.words[ 4]);
        r.words[12] = r.words[12] ^ r.words[ 0];
        r.words[12] = r.words[12].wrapping_shl( 8) | (r.words[12] >> 24);
        r.words[ 8] = r.words[ 8].wrapping_add(r.words[12]);
        r.words[ 4] = r.words[ 4] ^ r.words[ 8];
        r.words[ 4] = r.words[ 4].wrapping_shl( 7) | (r.words[ 4] >> 25);

        r.words[ 1] = r.words[ 1].wrapping_add(r.words[ 5]);
        r.words[13] = r.words[13] ^ r.words[ 1];
        r.words[13] = r.words[13].wrapping_shl(16) | (r.words[13] >> 16);
        r.words[ 9] = r.words[ 9].wrapping_add(r.words[13]);
        r.words[ 5] = r.words[ 5] ^ r.words[ 9];
        r.words[ 5] = r.words[ 5].wrapping_shl(12) | (r.words[ 5] >> 20);
        r.words[ 1] = r.words[ 1].wrapping_add(r.words[ 5]);
        r.words[13] = r.words[13] ^ r.words[ 1];
        r.words[13] = r.words[13].wrapping_shl( 8) | (r.words[13] >> 24);
        r.words[ 9] = r.words[ 9].wrapping_add(r.words[13]);
        r.words[ 5] = r.words[ 5] ^ r.words[ 9];
        r.words[ 5] = r.words[ 5].wrapping_shl( 7) | (r.words[ 5] >> 25);

        r.words[ 2] = r.words[ 2].wrapping_add(r.words[ 6]);
        r.words[14] = r.words[14] ^ r.words[ 2];
        r.words[14] = r.words[14].wrapping_shl(16) | (r.words[14] >> 16);
        r.words[10] = r.words[10].wrapping_add(r.words[14]);
        r.words[ 6] = r.words[ 6] ^ r.words[10];
        r.words[ 6] = r.words[ 6].wrapping_shl(12) | (r.words[ 6] >> 20);
        r.words[ 2] = r.words[ 2].wrapping_add(r.words[ 6]);
        r.words[14] = r.words[14] ^ r.words[ 2];
        r.words[14] = r.words[14].wrapping_shl( 8) | (r.words[14] >> 24);
        r.words[10] = r.words[10].wrapping_add(r.words[14]);
        r.words[ 6] = r.words[ 6] ^ r.words[10];
        r.words[ 6] = r.words[ 6].wrapping_shl( 7) | (r.words[ 6] >> 25);

        r.words[ 3] = r.words[ 3].wrapping_add(r.words[ 7]);
        r.words[15] = r.words[15] ^ r.words[ 3];
        r.words[15] = r.words[15].wrapping_shl(16) | (r.words[15] >> 16);
        r.words[11] = r.words[11].wrapping_add(r.words[15]);
        r.words[ 7] = r.words[ 7] ^ r.words[11];
        r.words[ 7] = r.words[ 7].wrapping_shl(12) | (r.words[ 7] >> 20);
        r.words[ 3] = r.words[ 3].wrapping_add(r.words[ 7]);
        r.words[15] = r.words[15] ^ r.words[ 3];
        r.words[15] = r.words[15].wrapping_shl( 8) | (r.words[15] >> 24);
        r.words[11] = r.words[11].wrapping_add(r.words[15]);
        r.words[ 7] = r.words[ 7] ^ r.words[11];
        r.words[ 7] = r.words[ 7].wrapping_shl( 7) | (r.words[ 7] >> 25);

        r.words[ 0] = r.words[ 0].wrapping_add(r.words[ 5]);
        r.words[15] = r.words[15] ^ r.words[ 0];
        r.words[15] = r.words[15].wrapping_shl(16) | (r.words[15] >> 16);
        r.words[10] = r.words[10].wrapping_add(r.words[15]);
        r.words[ 5] = r.words[ 5] ^ r.words[10];
        r.words[ 5] = r.words[ 5].wrapping_shl(12) | (r.words[ 5] >> 20);
        r.words[ 0] = r.words[ 0].wrapping_add(r.words[ 5]);
        r.words[15] = r.words[15] ^ r.words[ 0];
        r.words[15] = r.words[15].wrapping_shl( 8) | (r.words[15] >> 24);
        r.words[10] = r.words[10].wrapping_add(r.words[15]);
        r.words[ 5] = r.words[ 5] ^ r.words[10];
        r.words[ 5] = r.words[ 5].wrapping_shl( 7) | (r.words[ 5] >> 25);

        r.words[ 1] = r.words[ 1].wrapping_add(r.words[ 6]);
        r.words[12] = r.words[12] ^ r.words[ 1];
        r.words[12] = r.words[12].wrapping_shl(16) | (r.words[12] >> 16);
        r.words[11] = r.words[11].wrapping_add(r.words[12]);
        r.words[ 6] = r.words[ 6] ^ r.words[11];
        r.words[ 6] = r.words[ 6].wrapping_shl(12) | (r.words[ 6] >> 20);
        r.words[ 1] = r.words[ 1].wrapping_add(r.words[ 6]);
        r.words[12] = r.words[12] ^ r.words[ 1];
        r.words[12] = r.words[12].wrapping_shl( 8) | (r.words[12] >> 24);
        r.words[11] = r.words[11].wrapping_add(r.words[12]);
        r.words[ 6] = r.words[ 6] ^ r.words[11];
        r.words[ 6] = r.words[ 6].wrapping_shl( 7) | (r.words[ 6] >> 25);

        r.words[ 2] = r.words[ 2].wrapping_add(r.words[ 7]);
        r.words[13] = r.words[13] ^ r.words[ 2];
        r.words[13] = r.words[13].wrapping_shl(16) | (r.words[13] >> 16);
        r.words[ 8] = r.words[ 8].wrapping_add(r.words[13]);
        r.words[ 7] = r.words[ 7] ^ r.words[ 8];
        r.words[ 7] = r.words[ 7].wrapping_shl(12) | (r.words[ 7] >> 20);
        r.words[ 2] = r.words[ 2].wrapping_add(r.words[ 7]);
        r.words[13] = r.words[13] ^ r.words[ 2];
        r.words[13] = r.words[13].wrapping_shl( 8) | (r.words[13] >> 24);
        r.words[ 8] = r.words[ 8].wrapping_add(r.words[13]);
        r.words[ 7] = r.words[ 7] ^ r.words[ 8];
        r.words[ 7] = r.words[ 7].wrapping_shl( 7) | (r.words[ 7] >> 25);

        r.words[ 3] = r.words[ 3].wrapping_add(r.words[ 4]);
        r.words[14] = r.words[14] ^ r.words[ 3];
        r.words[14] = r.words[14].wrapping_shl(16) | (r.words[14] >> 16);
        r.words[ 9] = r.words[ 9].wrapping_add(r.words[14]);
        r.words[ 4] = r.words[ 4] ^ r.words[ 9];
        r.words[ 4] = r.words[ 4].wrapping_shl(12) | (r.words[ 4] >> 20);
        r.words[ 3] = r.words[ 3].wrapping_add(r.words[ 4]);
        r.words[14] = r.words[14] ^ r.words[ 3];
        r.words[14] = r.words[14].wrapping_shl( 8) | (r.words[14] >> 24);
        r.words[ 9] = r.words[ 9].wrapping_add(r.words[14]);
        r.words[ 4] = r.words[ 4] ^ r.words[ 9];
        r.words[ 4] = r.words[ 4].wrapping_shl( 7) | (r.words[ 4] >> 25);

    }

    for i in 0..16 {
        r.words[i] = r.words[i].wrapping_add(s.words[i]);
    }

    for i in 0..16 {
        let b: usize = i << 2;
        k[b + 0] =  r.words[i]        as u8;
        k[b + 1] = (r.words[i] >>  8) as u8;
        k[b + 2] = (r.words[i] >> 16) as u8;
        k[b + 3] = (r.words[i] >> 24) as u8;
    }

}