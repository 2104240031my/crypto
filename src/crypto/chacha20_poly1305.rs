use crate::crypto::aead::AeadStdFeature;
use crate::crypto::aead::AeadStdConst;
use crate::crypto::aead::AeadStdInstanceFn;
use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::Mac;
use crate::crypto::StreamCipher;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::poly1305::Poly1305;

pub struct ChaCha20Poly1305 {
    key: [u8; 32]
}

impl ChaCha20Poly1305 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            key: [0; 32]
        };
        v.rekey(key)?;
        return Ok(v);
    }

}

impl AeadStdFeature for ChaCha20Poly1305 {}

impl AeadStdConst for ChaCha20Poly1305 {
    const KEY_LEN: usize = ChaCha20::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12;
    const MAX_NONCE_LEN: usize = 12;
    const TAG_LEN: usize = Poly1305::MAC_LEN;
}

impl AeadStdInstanceFn for ChaCha20Poly1305 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() != 32 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.key.copy_from_slice(key);
        return Ok(self);

    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);

        if nonce.len() != 12 || len != ciphertext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut chacha20: ChaCha20 = ChaCha20::new(&self.key[..], nonce, 0)?;
        let mut key_strm: [u8; 64] = [0; 64];
        chacha20.block_unchecked(&mut key_strm[..]);
        chacha20.increment_counter()?;
        let mut poly1305: Poly1305 = Poly1305::new(&key_strm[..32])?;

        for i in (0..n).step_by(64) {
            chacha20.block_unchecked(&mut key_strm[..]);
            for j in i..(i + 64) {
                ciphertext[j] = plaintext[j] ^ key_strm[j - i];
            }
            chacha20.increment_counter()?;
        }

        if n != len {
            chacha20.block_unchecked(&mut key_strm[..]);
            for i in n..len {
                ciphertext[i] = plaintext[i] ^ key_strm[i - n];
            }
        }

        let pad: [u8; 16] = [0; 16];
        poly1305
            .update(aad)?
            .update(&pad[..((16 - (aad.len() & 15)) & 15)])?
            .update(ciphertext)?
            .update(&pad[..((16 - (len & 15)) & 15)])?
            .update(&(aad.len() as u64).to_le_bytes())?
            .update(&(len as u64).to_le_bytes())?
            .compute(tag)?;

        return Ok(());

    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {

        let len: usize = ciphertext.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);

        if nonce.len() != 12 || len != plaintext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut chacha20: ChaCha20 = ChaCha20::new(&self.key[..], nonce, 0)?;
        let mut key_strm: [u8; 64] = [0; 64];
        chacha20.block_unchecked(&mut key_strm[..]);
        chacha20.increment_counter()?;
        let mut poly1305: Poly1305 = Poly1305::new(&key_strm[..32])?;

        let mut t: [u8; 16] = [0; 16];
        let pad: [u8; 16] = [0; 16];
        poly1305
            .update(aad)?
            .update(&pad[..((16 - (aad.len() & 15)) & 15)])?
            .update(ciphertext)?
            .update(&pad[..((16 - (len & 15)) & 15)])?
            .update(&(aad.len() as u64).to_le_bytes())?
            .update(&(len as u64).to_le_bytes())?
            .compute(&mut t[..])?;

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ t[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        for i in (0..n).step_by(64) {
            chacha20.block_unchecked(&mut key_strm[..]);
            for j in i..(i + 64) {
                plaintext[j] = ciphertext[j] ^ key_strm[j - i];
            }
            chacha20.increment_counter()?;
        }

        if n != len {
            chacha20.block_unchecked(&mut key_strm[..]);
            for i in n..len {
                plaintext[i] = ciphertext[i] ^ key_strm[i - n];
            }
        }

        return Ok(true);

    }

}