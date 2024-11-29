use crate::crypto::error::CryptoError;
use crate::crypto::BlockCipher;
use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ccm128;
use crate::crypto::block_cipher_mode::Gcm128;
use crate::crypto::chacha20_poly1305::ChaCha20Poly1305;

pub trait AeadStdFeature: AeadStdConst + AeadStdInstanceFn {}

pub trait AeadStdConst {
    const KEY_LEN: usize;
    const MIN_NONCE_LEN: usize;
    const MAX_NONCE_LEN: usize;
    const TAG_LEN: usize;
}

pub trait AeadStdInstanceFn {
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError>;
}

pub enum AeadAlgorithm {
    Null,
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub enum Aead {
    Null(()),
    Aes128Ccm(Aes128),
    Aes192Ccm(Aes192),
    Aes256Ccm(Aes256),
    Aes128Gcm(Aes128),
    Aes192Gcm(Aes192),
    Aes256Gcm(Aes256),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Aead {

    pub fn new(&mut self, key: &[u8]) -> Result<Self, CryptoError> {
        return match self {
            AeadAlgorithm::Null             => Ok(Self::Null(())),
            AeadAlgorithm::Aes128Ccm        => Ok(Self::Aes128Ccm(Aes128::new(key)?)),
            AeadAlgorithm::Aes192Ccm        => Ok(Self::Aes192Ccm(Aes192::new(key)?)),
            AeadAlgorithm::Aes256Ccm        => Ok(Self::Aes256Ccm(Aes256::new(key)?)),
            AeadAlgorithm::Aes128Gcm        => Ok(Self::Aes128Gcm(Aes128::new(key)?)),
            AeadAlgorithm::Aes192Gcm        => Ok(Self::Aes192Gcm(Aes192::new(key)?)),
            AeadAlgorithm::Aes256Gcm        => Ok(Self::Aes256Gcm(Aes256::new(key)?)),
            AeadAlgorithm::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new(key)?)),
        };
    }

}

impl AeadStdInstanceFn for Aead {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return match self {
            Self::Null(())            => Ok(self),
            Self::Aes128Ccm(v)        => v.rekey(key),
            Self::Aes192Ccm(v)        => v.rekey(key),
            Self::Aes256Ccm(v)        => v.rekey(key),
            Self::Aes128Gcm(v)        => v.rekey(key),
            Self::Aes192Gcm(v)        => v.rekey(key),
            Self::Aes256Gcm(v)        => v.rekey(key),
            Self::ChaCha20Poly1305(v) => v.rekey(key),
        };
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Null(())            => Ok(()),
            Self::Aes128Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes128Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Null(())            => Ok(()),
            Self::Aes128Ccm(v)        => BlockCipherMode128::ccm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Ccm(v)        => BlockCipherMode128::ccm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Ccm(v)        => BlockCipherMode128::ccm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::Aes128Gcm(v)        => BlockCipherMode128::gcm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Gcm(v)        => BlockCipherMode128::gcm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Gcm(v)        => BlockCipherMode128::gcm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
        };
    }

}