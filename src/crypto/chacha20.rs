use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::StreamCipher;

pub struct ChaCha20 {
    w: [u32; 16]
}

pub struct ChaCha20Cipher {
    key: [u8; 32]
}

impl ChaCha20 {

    pub fn new(key: &[u8], nonce: &[u8], counter: u32) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            w: [0; 16]
        };
        v.reseed(key, nonce, counter)?;
        return Ok(v);
    }

    pub fn reseed(&mut self, key: &[u8], nonce: &[u8], counter: u32) -> Result<(), CryptoError> {

        if key.len() != 32 || nonce.len() != 12 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        chacha20_reseed(self, key, nonce, counter);
        return Ok(());

    }

    pub fn block(&self, key_strm: &mut [u8]) -> Result<(), CryptoError> {

        if key_strm.len() != 64 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        chacha20_block(self, key_strm);
        return Ok(());

    }

    pub fn increment_counter(&mut self) -> Result<(), CryptoError> {
        self.w[12] = self.w[12] + 1;
        return Ok(());
    }

}

impl ChaCha20Cipher {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            key: [0; 32]
        };

        v.rekey(key)?;
        return Ok(v);

    }

    pub fn encrypt_or_decrypt_with_counter(&mut self, nonce: &[u8], counter: u32, intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);

        if nonce.len() != 12 || len != outtext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut state: ChaCha20 = ChaCha20::new(&self.key[..], nonce, counter)?;
        let mut key_strm: [u8; 64] = [0; 64];

        for i in (0..n).step_by(64) {
            state.block(&mut key_strm[..])?;
            for j in i..(i + 64) {
                outtext[j] = intext[j] ^ key_strm[j - i];
            }
            state.increment_counter()?;
        }

        if n != len {
            state.block(&mut key_strm[..])?;
            for i in n..len {
                outtext[i] = intext[i] ^ key_strm[i - n];
            }
            state.increment_counter()?;
        }

        return Ok(());

    }

}

impl StreamCipher for ChaCha20Cipher  {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if key.len() != 32 {
            Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect))
        } else {
            self.key.copy_from_slice(key);
            Ok(self)
        };
    }

    fn encrypt_or_decrypt(&mut self, nonce: &[u8], intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {
        return self.encrypt_or_decrypt_with_counter(nonce, 1, intext, outtext);
    }

}

const CHACHA20_CONST_W0: u32 = 0x61707865;
const CHACHA20_CONST_W1: u32 = 0x3320646e;
const CHACHA20_CONST_W2: u32 = 0x79622d32;
const CHACHA20_CONST_W3: u32 = 0x6b206574;

fn chacha20_reseed(s: &mut ChaCha20, k: &[u8], n: &[u8], c: u32) {
    s.w[0]  = CHACHA20_CONST_W0;
    s.w[1]  = CHACHA20_CONST_W1;
    s.w[2]  = CHACHA20_CONST_W2;
    s.w[3]  = CHACHA20_CONST_W3;
    s.w[4]  = ((k[ 3] as u32) << 24) | ((k[ 2] as u32) << 16) | ((k[ 1] as u32) << 8) | (k[ 0] as u32);
    s.w[5]  = ((k[ 7] as u32) << 24) | ((k[ 6] as u32) << 16) | ((k[ 5] as u32) << 8) | (k[ 4] as u32);
    s.w[6]  = ((k[11] as u32) << 24) | ((k[10] as u32) << 16) | ((k[ 9] as u32) << 8) | (k[ 8] as u32);
    s.w[7]  = ((k[15] as u32) << 24) | ((k[14] as u32) << 16) | ((k[13] as u32) << 8) | (k[12] as u32);
    s.w[8]  = ((k[19] as u32) << 24) | ((k[18] as u32) << 16) | ((k[17] as u32) << 8) | (k[16] as u32);
    s.w[9]  = ((k[23] as u32) << 24) | ((k[22] as u32) << 16) | ((k[21] as u32) << 8) | (k[20] as u32);
    s.w[10] = ((k[27] as u32) << 24) | ((k[26] as u32) << 16) | ((k[25] as u32) << 8) | (k[24] as u32);
    s.w[11] = ((k[31] as u32) << 24) | ((k[30] as u32) << 16) | ((k[29] as u32) << 8) | (k[28] as u32);
    s.w[12] = c;
    s.w[13] = ((n[ 3] as u32) << 24) | ((n[ 2] as u32) << 16) | ((n[ 1] as u32) << 8) | (n[ 0] as u32);
    s.w[14] = ((n[ 7] as u32) << 24) | ((n[ 6] as u32) << 16) | ((n[ 5] as u32) << 8) | (n[ 4] as u32);
    s.w[15] = ((n[11] as u32) << 24) | ((n[10] as u32) << 16) | ((n[ 9] as u32) << 8) | (n[ 8] as u32);
}

fn chacha20_block(s: &ChaCha20, k: &mut [u8]) {

    let mut r: ChaCha20 = ChaCha20{ w: [
        s.w[ 0], s.w[ 1], s.w[ 2], s.w[ 3],
        s.w[ 4], s.w[ 5], s.w[ 6], s.w[ 7],
        s.w[ 8], s.w[ 9], s.w[10], s.w[11],
        s.w[12], s.w[13], s.w[14], s.w[15]
    ]};

    for _ in 0..10 {

        r.w[ 0] = r.w[ 0].wrapping_add(r.w[ 4]);
        r.w[12] = r.w[12] ^ r.w[ 0];
        r.w[12] = r.w[12].wrapping_shl(16) | (r.w[12] >> 16);
        r.w[ 8] = r.w[ 8].wrapping_add(r.w[12]);
        r.w[ 4] = r.w[ 4] ^ r.w[ 8];
        r.w[ 4] = r.w[ 4].wrapping_shl(12) | (r.w[ 4] >> 20);
        r.w[ 0] = r.w[ 0].wrapping_add(r.w[ 4]);
        r.w[12] = r.w[12] ^ r.w[ 0];
        r.w[12] = r.w[12].wrapping_shl( 8) | (r.w[12] >> 24);
        r.w[ 8] = r.w[ 8].wrapping_add(r.w[12]);
        r.w[ 4] = r.w[ 4] ^ r.w[ 8];
        r.w[ 4] = r.w[ 4].wrapping_shl( 7) | (r.w[ 4] >> 25);

        r.w[ 1] = r.w[ 1].wrapping_add(r.w[ 5]);
        r.w[13] = r.w[13] ^ r.w[ 1];
        r.w[13] = r.w[13].wrapping_shl(16) | (r.w[13] >> 16);
        r.w[ 9] = r.w[ 9].wrapping_add(r.w[13]);
        r.w[ 5] = r.w[ 5] ^ r.w[ 9];
        r.w[ 5] = r.w[ 5].wrapping_shl(12) | (r.w[ 5] >> 20);
        r.w[ 1] = r.w[ 1].wrapping_add(r.w[ 5]);
        r.w[13] = r.w[13] ^ r.w[ 1];
        r.w[13] = r.w[13].wrapping_shl( 8) | (r.w[13] >> 24);
        r.w[ 9] = r.w[ 9].wrapping_add(r.w[13]);
        r.w[ 5] = r.w[ 5] ^ r.w[ 9];
        r.w[ 5] = r.w[ 5].wrapping_shl( 7) | (r.w[ 5] >> 25);

        r.w[ 2] = r.w[ 2].wrapping_add(r.w[ 6]);
        r.w[14] = r.w[14] ^ r.w[ 2];
        r.w[14] = r.w[14].wrapping_shl(16) | (r.w[14] >> 16);
        r.w[10] = r.w[10].wrapping_add(r.w[14]);
        r.w[ 6] = r.w[ 6] ^ r.w[10];
        r.w[ 6] = r.w[ 6].wrapping_shl(12) | (r.w[ 6] >> 20);
        r.w[ 2] = r.w[ 2].wrapping_add(r.w[ 6]);
        r.w[14] = r.w[14] ^ r.w[ 2];
        r.w[14] = r.w[14].wrapping_shl( 8) | (r.w[14] >> 24);
        r.w[10] = r.w[10].wrapping_add(r.w[14]);
        r.w[ 6] = r.w[ 6] ^ r.w[10];
        r.w[ 6] = r.w[ 6].wrapping_shl( 7) | (r.w[ 6] >> 25);

        r.w[ 3] = r.w[ 3].wrapping_add(r.w[ 7]);
        r.w[15] = r.w[15] ^ r.w[ 3];
        r.w[15] = r.w[15].wrapping_shl(16) | (r.w[15] >> 16);
        r.w[11] = r.w[11].wrapping_add(r.w[15]);
        r.w[ 7] = r.w[ 7] ^ r.w[11];
        r.w[ 7] = r.w[ 7].wrapping_shl(12) | (r.w[ 7] >> 20);
        r.w[ 3] = r.w[ 3].wrapping_add(r.w[ 7]);
        r.w[15] = r.w[15] ^ r.w[ 3];
        r.w[15] = r.w[15].wrapping_shl( 8) | (r.w[15] >> 24);
        r.w[11] = r.w[11].wrapping_add(r.w[15]);
        r.w[ 7] = r.w[ 7] ^ r.w[11];
        r.w[ 7] = r.w[ 7].wrapping_shl( 7) | (r.w[ 7] >> 25);

        r.w[ 0] = r.w[ 0].wrapping_add(r.w[ 5]);
        r.w[15] = r.w[15] ^ r.w[ 0];
        r.w[15] = r.w[15].wrapping_shl(16) | (r.w[15] >> 16);
        r.w[10] = r.w[10].wrapping_add(r.w[15]);
        r.w[ 5] = r.w[ 5] ^ r.w[10];
        r.w[ 5] = r.w[ 5].wrapping_shl(12) | (r.w[ 5] >> 20);
        r.w[ 0] = r.w[ 0].wrapping_add(r.w[ 5]);
        r.w[15] = r.w[15] ^ r.w[ 0];
        r.w[15] = r.w[15].wrapping_shl( 8) | (r.w[15] >> 24);
        r.w[10] = r.w[10].wrapping_add(r.w[15]);
        r.w[ 5] = r.w[ 5] ^ r.w[10];
        r.w[ 5] = r.w[ 5].wrapping_shl( 7) | (r.w[ 5] >> 25);

        r.w[ 1] = r.w[ 1].wrapping_add(r.w[ 6]);
        r.w[12] = r.w[12] ^ r.w[ 1];
        r.w[12] = r.w[12].wrapping_shl(16) | (r.w[12] >> 16);
        r.w[11] = r.w[11].wrapping_add(r.w[12]);
        r.w[ 6] = r.w[ 6] ^ r.w[11];
        r.w[ 6] = r.w[ 6].wrapping_shl(12) | (r.w[ 6] >> 20);
        r.w[ 1] = r.w[ 1].wrapping_add(r.w[ 6]);
        r.w[12] = r.w[12] ^ r.w[ 1];
        r.w[12] = r.w[12].wrapping_shl( 8) | (r.w[12] >> 24);
        r.w[11] = r.w[11].wrapping_add(r.w[12]);
        r.w[ 6] = r.w[ 6] ^ r.w[11];
        r.w[ 6] = r.w[ 6].wrapping_shl( 7) | (r.w[ 6] >> 25);

        r.w[ 2] = r.w[ 2].wrapping_add(r.w[ 7]);
        r.w[13] = r.w[13] ^ r.w[ 2];
        r.w[13] = r.w[13].wrapping_shl(16) | (r.w[13] >> 16);
        r.w[ 8] = r.w[ 8].wrapping_add(r.w[13]);
        r.w[ 7] = r.w[ 7] ^ r.w[ 8];
        r.w[ 7] = r.w[ 7].wrapping_shl(12) | (r.w[ 7] >> 20);
        r.w[ 2] = r.w[ 2].wrapping_add(r.w[ 7]);
        r.w[13] = r.w[13] ^ r.w[ 2];
        r.w[13] = r.w[13].wrapping_shl( 8) | (r.w[13] >> 24);
        r.w[ 8] = r.w[ 8].wrapping_add(r.w[13]);
        r.w[ 7] = r.w[ 7] ^ r.w[ 8];
        r.w[ 7] = r.w[ 7].wrapping_shl( 7) | (r.w[ 7] >> 25);

        r.w[ 3] = r.w[ 3].wrapping_add(r.w[ 4]);
        r.w[14] = r.w[14] ^ r.w[ 3];
        r.w[14] = r.w[14].wrapping_shl(16) | (r.w[14] >> 16);
        r.w[ 9] = r.w[ 9].wrapping_add(r.w[14]);
        r.w[ 4] = r.w[ 4] ^ r.w[ 9];
        r.w[ 4] = r.w[ 4].wrapping_shl(12) | (r.w[ 4] >> 20);
        r.w[ 3] = r.w[ 3].wrapping_add(r.w[ 4]);
        r.w[14] = r.w[14] ^ r.w[ 3];
        r.w[14] = r.w[14].wrapping_shl( 8) | (r.w[14] >> 24);
        r.w[ 9] = r.w[ 9].wrapping_add(r.w[14]);
        r.w[ 4] = r.w[ 4] ^ r.w[ 9];
        r.w[ 4] = r.w[ 4].wrapping_shl( 7) | (r.w[ 4] >> 25);

    }

    for i in 0..16 {
        r.w[i] = r.w[i].wrapping_add(s.w[i]);
    }

    for i in 0..16 {
        let b: usize = i << 2;
        k[b + 0] =  r.w[i]        as u8;
        k[b + 1] = (r.w[i] >>  8) as u8;
        k[b + 2] = (r.w[i] >> 16) as u8;
        k[b + 3] = (r.w[i] >> 24) as u8;
    }

}