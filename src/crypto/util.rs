use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::aes_aead::Aes128Ccm;
use crate::crypto::aes_aead::Aes192Ccm;
use crate::crypto::aes_aead::Aes256Ccm;
use crate::crypto::aes_aead::Aes128Gcm;
use crate::crypto::aes_aead::Aes192Gcm;
use crate::crypto::aes_aead::Aes256Gcm;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ecb128;
use crate::crypto::block_cipher_mode::Cbc128;
use crate::crypto::block_cipher_mode::Ofb128;
use crate::crypto::block_cipher_mode::Cfb128Fb8;
use crate::crypto::block_cipher_mode::Cfb128Fb128;
use crate::crypto::block_cipher_mode::Ctr128;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::chacha20_poly1305::ChaCha20Poly1305;
use crate::crypto::ed25519::Ed25519Signer;
use crate::crypto::ed25519::Ed25519Verifier;
use crate::crypto::error::CryptoError;
use crate::crypto::feature::Aead as AeadFeature;
use crate::crypto::feature::BlockCipher as BlockCipherFeature;
use crate::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use crate::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use crate::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use crate::crypto::feature::Hash as HashFeature;
use crate::crypto::feature::Mac as MacFeature;
use crate::crypto::feature::StreamCipher as StreamCipherFeature;
use crate::crypto::feature::Xof as XofFeature;
use crate::crypto::hmac_sha2::HmacSha224;
use crate::crypto::hmac_sha2::HmacSha256;
use crate::crypto::hmac_sha2::HmacSha384;
use crate::crypto::hmac_sha2::HmacSha512;
use crate::crypto::hmac_sha3::HmacSha3224;
use crate::crypto::hmac_sha3::HmacSha3256;
use crate::crypto::hmac_sha3::HmacSha3384;
use crate::crypto::hmac_sha3::HmacSha3512;
use crate::crypto::poly1305::Poly1305;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::sha2::Sha512224;
use crate::crypto::sha2::Sha512256;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;
use crate::crypto::sha3::Shake128;
use crate::crypto::sha3::Shake256;
use crate::crypto::x25519::X25519;

#[derive(Clone, Copy)]
pub enum AeadAlgorithm {
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub enum Aead {
    Aes128Ccm(Aes128Ccm),
    Aes192Ccm(Aes192Ccm),
    Aes256Ccm(Aes256Ccm),
    Aes128Gcm(Aes128Gcm),
    Aes192Gcm(Aes192Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadAlgorithm {

    pub fn key_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::KEY_LEN,
            Self::Aes192Ccm        => Aes192Ccm::KEY_LEN,
            Self::Aes256Ccm        => Aes256Ccm::KEY_LEN,
            Self::Aes128Gcm        => Aes128Gcm::KEY_LEN,
            Self::Aes192Gcm        => Aes192Gcm::KEY_LEN,
            Self::Aes256Gcm        => Aes256Gcm::KEY_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::KEY_LEN,
        };
    }

    pub fn min_nonce_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::MIN_NONCE_LEN,
            Self::Aes192Ccm        => Aes192Ccm::MIN_NONCE_LEN,
            Self::Aes256Ccm        => Aes256Ccm::MIN_NONCE_LEN,
            Self::Aes128Gcm        => Aes128Gcm::MIN_NONCE_LEN,
            Self::Aes192Gcm        => Aes192Gcm::MIN_NONCE_LEN,
            Self::Aes256Gcm        => Aes256Gcm::MIN_NONCE_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::MIN_NONCE_LEN,
        };
    }

    pub fn max_nonce_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::MAX_NONCE_LEN,
            Self::Aes192Ccm        => Aes192Ccm::MAX_NONCE_LEN,
            Self::Aes256Ccm        => Aes256Ccm::MAX_NONCE_LEN,
            Self::Aes128Gcm        => Aes128Gcm::MAX_NONCE_LEN,
            Self::Aes192Gcm        => Aes192Gcm::MAX_NONCE_LEN,
            Self::Aes256Gcm        => Aes256Gcm::MAX_NONCE_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::MAX_NONCE_LEN,
        };
    }

    pub fn tag_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::TAG_LEN,
            Self::Aes192Ccm        => Aes192Ccm::TAG_LEN,
            Self::Aes256Ccm        => Aes256Ccm::TAG_LEN,
            Self::Aes128Gcm        => Aes128Gcm::TAG_LEN,
            Self::Aes192Gcm        => Aes192Gcm::TAG_LEN,
            Self::Aes256Gcm        => Aes256Gcm::TAG_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::TAG_LEN,
        };
    }

}

impl Aead {

    pub fn new(algo: AeadAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            AeadAlgorithm::Aes128Ccm        => Ok(Self::Aes128Ccm(Aes128Ccm::new(key)?)),
            AeadAlgorithm::Aes192Ccm        => Ok(Self::Aes192Ccm(Aes192Ccm::new(key)?)),
            AeadAlgorithm::Aes256Ccm        => Ok(Self::Aes256Ccm(Aes256Ccm::new(key)?)),
            AeadAlgorithm::Aes128Gcm        => Ok(Self::Aes128Gcm(Aes128Gcm::new(key)?)),
            AeadAlgorithm::Aes192Gcm        => Ok(Self::Aes192Gcm(Aes192Gcm::new(key)?)),
            AeadAlgorithm::Aes256Gcm        => Ok(Self::Aes256Gcm(Aes256Gcm::new(key)?)),
            AeadAlgorithm::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Aes128Ccm(v)        => v.rekey(key).err(),
            Self::Aes192Ccm(v)        => v.rekey(key).err(),
            Self::Aes256Ccm(v)        => v.rekey(key).err(),
            Self::Aes128Gcm(v)        => v.rekey(key).err(),
            Self::Aes192Gcm(v)        => v.rekey(key).err(),
            Self::Aes256Gcm(v)        => v.rekey(key).err(),
            Self::ChaCha20Poly1305(v) => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

    pub fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes192Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
        };
    }

    pub fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes192Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes256Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes192Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
        };
    }

    pub fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes192Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes256Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes192Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
        };
    }

}

#[derive(Clone, Copy)]
pub enum CipherAlgorithm {
    Aes128Ecb,
    Aes192Ecb,
    Aes256Ecb,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128CfbFb8,
    Aes192CfbFb8,
    Aes256CfbFb8,
    Aes128CfbFb128,
    Aes192CfbFb128,
    Aes256CfbFb128,
    Aes128Ofb,
    Aes192Ofb,
    Aes256Ofb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    ChaCha20,
}

pub enum Cipher {
    Aes128Ecb(Aes128),
    Aes192Ecb(Aes192),
    Aes256Ecb(Aes256),
    Aes128Cbc(Aes128),
    Aes192Cbc(Aes192),
    Aes256Cbc(Aes256),
    Aes128CfbFb8(Aes128),
    Aes192CfbFb8(Aes192),
    Aes256CfbFb8(Aes256),
    Aes128CfbFb128(Aes128),
    Aes192CfbFb128(Aes192),
    Aes256CfbFb128(Aes256),
    Aes128Ofb(Aes128),
    Aes192Ofb(Aes192),
    Aes256Ofb(Aes256),
    Aes128Ctr(Aes128),
    Aes192Ctr(Aes192),
    Aes256Ctr(Aes256),
    ChaCha20(ChaCha20),
}

impl CipherAlgorithm {

    pub fn key_len(&self) -> usize {
        return match self {
            Self::Aes128Ecb      => Aes128::KEY_LEN,
            Self::Aes192Ecb      => Aes192::KEY_LEN,
            Self::Aes256Ecb      => Aes256::KEY_LEN,
            Self::Aes128Cbc      => Aes128::KEY_LEN,
            Self::Aes192Cbc      => Aes192::KEY_LEN,
            Self::Aes256Cbc      => Aes256::KEY_LEN,
            Self::Aes128CfbFb8   => Aes128::KEY_LEN,
            Self::Aes192CfbFb8   => Aes192::KEY_LEN,
            Self::Aes256CfbFb8   => Aes256::KEY_LEN,
            Self::Aes128CfbFb128 => Aes128::KEY_LEN,
            Self::Aes192CfbFb128 => Aes192::KEY_LEN,
            Self::Aes256CfbFb128 => Aes256::KEY_LEN,
            Self::Aes128Ofb      => Aes128::KEY_LEN,
            Self::Aes192Ofb      => Aes192::KEY_LEN,
            Self::Aes256Ofb      => Aes256::KEY_LEN,
            Self::Aes128Ctr      => Aes128::KEY_LEN,
            Self::Aes192Ctr      => Aes192::KEY_LEN,
            Self::Aes256Ctr      => Aes256::KEY_LEN,
            Self::ChaCha20       => ChaCha20::KEY_LEN,
        };
    }

    pub fn iv_len(&self) -> usize {
        return match self {
            Self::Aes128Ecb      => 0,
            Self::Aes192Ecb      => 0,
            Self::Aes256Ecb      => 0,
            Self::Aes128Cbc      => Aes128::BLOCK_SIZE,
            Self::Aes192Cbc      => Aes192::BLOCK_SIZE,
            Self::Aes256Cbc      => Aes256::BLOCK_SIZE,
            Self::Aes128CfbFb8   => Aes128::BLOCK_SIZE,
            Self::Aes192CfbFb8   => Aes192::BLOCK_SIZE,
            Self::Aes256CfbFb8   => Aes256::BLOCK_SIZE,
            Self::Aes128CfbFb128 => Aes128::BLOCK_SIZE,
            Self::Aes192CfbFb128 => Aes192::BLOCK_SIZE,
            Self::Aes256CfbFb128 => Aes256::BLOCK_SIZE,
            Self::Aes128Ofb      => Aes128::BLOCK_SIZE,
            Self::Aes192Ofb      => Aes192::BLOCK_SIZE,
            Self::Aes256Ofb      => Aes256::BLOCK_SIZE,
            Self::Aes128Ctr      => Aes128::BLOCK_SIZE,
            Self::Aes192Ctr      => Aes192::BLOCK_SIZE,
            Self::Aes256Ctr      => Aes256::BLOCK_SIZE,
            Self::ChaCha20       => 12,
        };
    }

}

impl Cipher {

    pub fn new(algo: CipherAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            CipherAlgorithm::Aes128Ecb      => Ok(Self::Aes128Ecb(Aes128::new(key)?)),
            CipherAlgorithm::Aes192Ecb      => Ok(Self::Aes192Ecb(Aes192::new(key)?)),
            CipherAlgorithm::Aes256Ecb      => Ok(Self::Aes256Ecb(Aes256::new(key)?)),
            CipherAlgorithm::Aes128Cbc      => Ok(Self::Aes128Cbc(Aes128::new(key)?)),
            CipherAlgorithm::Aes192Cbc      => Ok(Self::Aes192Cbc(Aes192::new(key)?)),
            CipherAlgorithm::Aes256Cbc      => Ok(Self::Aes256Cbc(Aes256::new(key)?)),
            CipherAlgorithm::Aes128CfbFb8   => Ok(Self::Aes128CfbFb8(Aes128::new(key)?)),
            CipherAlgorithm::Aes192CfbFb8   => Ok(Self::Aes192CfbFb8(Aes192::new(key)?)),
            CipherAlgorithm::Aes256CfbFb8   => Ok(Self::Aes256CfbFb8(Aes256::new(key)?)),
            CipherAlgorithm::Aes128CfbFb128 => Ok(Self::Aes128CfbFb128(Aes128::new(key)?)),
            CipherAlgorithm::Aes192CfbFb128 => Ok(Self::Aes192CfbFb128(Aes192::new(key)?)),
            CipherAlgorithm::Aes256CfbFb128 => Ok(Self::Aes256CfbFb128(Aes256::new(key)?)),
            CipherAlgorithm::Aes128Ofb      => Ok(Self::Aes128Ofb(Aes128::new(key)?)),
            CipherAlgorithm::Aes192Ofb      => Ok(Self::Aes192Ofb(Aes192::new(key)?)),
            CipherAlgorithm::Aes256Ofb      => Ok(Self::Aes256Ofb(Aes256::new(key)?)),
            CipherAlgorithm::Aes128Ctr      => Ok(Self::Aes128Ctr(Aes128::new(key)?)),
            CipherAlgorithm::Aes192Ctr      => Ok(Self::Aes192Ctr(Aes192::new(key)?)),
            CipherAlgorithm::Aes256Ctr      => Ok(Self::Aes256Ctr(Aes256::new(key)?)),
            CipherAlgorithm::ChaCha20       => Ok(Self::ChaCha20(ChaCha20::new(key, &[0; 12][..], 1)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Aes128Ecb(v)      => v.rekey(key).err(),
            Self::Aes192Ecb(v)      => v.rekey(key).err(),
            Self::Aes256Ecb(v)      => v.rekey(key).err(),
            Self::Aes128Cbc(v)      => v.rekey(key).err(),
            Self::Aes192Cbc(v)      => v.rekey(key).err(),
            Self::Aes256Cbc(v)      => v.rekey(key).err(),
            Self::Aes128CfbFb8(v)   => v.rekey(key).err(),
            Self::Aes192CfbFb8(v)   => v.rekey(key).err(),
            Self::Aes256CfbFb8(v)   => v.rekey(key).err(),
            Self::Aes128CfbFb128(v) => v.rekey(key).err(),
            Self::Aes192CfbFb128(v) => v.rekey(key).err(),
            Self::Aes256CfbFb128(v) => v.rekey(key).err(),
            Self::Aes128Ofb(v)      => v.rekey(key).err(),
            Self::Aes192Ofb(v)      => v.rekey(key).err(),
            Self::Aes256Ofb(v)      => v.rekey(key).err(),
            Self::Aes128Ctr(v)      => v.rekey(key).err(),
            Self::Aes192Ctr(v)      => v.rekey(key).err(),
            Self::Aes256Ctr(v)      => v.rekey(key).err(),
            Self::ChaCha20(v)       => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn encrypt(&mut self, iv: &mut [u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes192Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes256Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes128Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes192Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes256Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes128CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes192CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes256CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes128CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes192CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes256CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes128Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes192Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes256Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes128Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::Aes192Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::Aes256Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::ChaCha20(v)       => v.reset(iv, 1)?.encrypt_or_decrypt(plaintext, ciphertext),
        };
    }

    pub fn decrypt(&mut self, iv: &mut [u8], ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks(v, ciphertext, plaintext),
            Self::Aes192Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks(v, ciphertext, plaintext),
            Self::Aes256Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks(v, ciphertext, plaintext),
            Self::Aes128Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks(v, iv, ciphertext, plaintext),
            Self::Aes192Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks(v, iv, ciphertext, plaintext),
            Self::Aes256Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks(v, iv, ciphertext, plaintext),
            Self::Aes128CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes192CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes256CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes128CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes192CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes256CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes128Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes192Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes256Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, ciphertext, plaintext),
            Self::Aes128Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, ciphertext, plaintext),
            Self::Aes192Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, ciphertext, plaintext),
            Self::Aes256Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, ciphertext, plaintext),
            Self::ChaCha20(v)       => v.reset(iv, 1)?.encrypt_or_decrypt(ciphertext, plaintext),
        };
    }

    pub fn encrypt_overwrite(&mut self, iv: &mut [u8], text: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks_overwrite(v, text),
            Self::Aes192Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks_overwrite(v, text),
            Self::Aes256Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks_overwrite(v, text),
            Self::Aes128Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks_overwrite(v, iv, text),
            Self::Aes192Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks_overwrite(v, iv, text),
            Self::Aes256Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks_overwrite(v, iv, text),
            Self::Aes128CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt_overwrite(v, iv, text),
            Self::Aes192CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt_overwrite(v, iv, text),
            Self::Aes256CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt_overwrite(v, iv, text),
            Self::Aes128CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt_overwrite(v, iv, text),
            Self::Aes192CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt_overwrite(v, iv, text),
            Self::Aes256CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt_overwrite(v, iv, text),
            Self::Aes128Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes192Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes256Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes128Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::Aes192Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::Aes256Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::ChaCha20(v)       => v.reset(iv, 1)?.encrypt_or_decrypt_overwrite(text),
        };
    }

    pub fn decrypt_overwrite(&mut self, iv: &mut [u8], text: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks_overwrite(v, text),
            Self::Aes192Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks_overwrite(v, text),
            Self::Aes256Ecb(v)      => BlockCipherMode128::ecb_decrypt_blocks_overwrite(v, text),
            Self::Aes128Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks_overwrite(v, iv, text),
            Self::Aes192Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks_overwrite(v, iv, text),
            Self::Aes256Cbc(v)      => BlockCipherMode128::cbc_decrypt_blocks_overwrite(v, iv, text),
            Self::Aes128CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt_overwrite(v, iv, text),
            Self::Aes192CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt_overwrite(v, iv, text),
            Self::Aes256CfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt_overwrite(v, iv, text),
            Self::Aes128CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt_overwrite(v, iv, text),
            Self::Aes192CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt_overwrite(v, iv, text),
            Self::Aes256CfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt_overwrite(v, iv, text),
            Self::Aes128Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes192Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes256Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(v, iv, text),
            Self::Aes128Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::Aes192Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::Aes256Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(v, iv, 16, text),
            Self::ChaCha20(v)       => v.reset(iv, 1)?.encrypt_or_decrypt_overwrite(text),
        };
    }

}

#[derive(Clone, Copy)]
pub enum DiffieHellmanAlgorithm {
    X25519,
}

pub enum DiffieHellman {
    X25519(X25519),
}

impl DiffieHellmanAlgorithm {

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PUBLIC_KEY_LEN,
        };
    }

    pub fn shared_secret_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::SHARED_SECRET_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn compute_shared_secret_oneshot(&self, priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_shared_secret_oneshot(priv_key,
                peer_pub_key, shared_secret),
        };
    }

}

#[derive(Clone, Copy)]
pub enum DigitalSignatureAlgorithm {
    Ed25519,
}

pub enum DigitalSignatureSigner {
    Ed25519(Ed25519Signer),
}

pub enum DigitalSignatureVerifier {
    Ed25519(Ed25519Verifier),
}

impl DigitalSignatureAlgorithm {

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PUBLIC_KEY_LEN,
        };
    }

    pub fn signature_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::SIGNATURE_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn sign_oneshot(&self, priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::sign_oneshot(priv_key, msg, signature),
        };
    }

    pub fn verify_oneshot(&self, pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Verifier::verify_oneshot(pub_key, msg, signature),
        };
    }

}

impl DigitalSignatureSigner {

    pub fn new(algo: DigitalSignatureAlgorithm, priv_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Signer::new(priv_key)?)),
        };
    }

    pub fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(priv_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.compute_public_key(pub_key),
        };
    }

    pub fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.sign(msg, signature),
        };
    }

}

impl DigitalSignatureVerifier {

    pub fn new(algo: DigitalSignatureAlgorithm, pub_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Verifier::new(pub_key)?)),
        };
    }

    pub fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(pub_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519(v) => v.verify(msg, signature),
        };
    }

}

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512224,
    Sha512256,
    Sha3224,
    Sha3256,
    Sha3384,
    Sha3512,
}

pub enum Hash {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512224(Sha512224),
    Sha512256(Sha512256),
    Sha3224(Sha3224),
    Sha3256(Sha3256),
    Sha3384(Sha3384),
    Sha3512(Sha3512),
}

impl HashAlgorithm {

    pub fn md_len(&self) -> usize {
        return match self {
            Self::Sha224    => Sha224::MESSAGE_DIGEST_LEN,
            Self::Sha256    => Sha256::MESSAGE_DIGEST_LEN,
            Self::Sha384    => Sha384::MESSAGE_DIGEST_LEN,
            Self::Sha512    => Sha512::MESSAGE_DIGEST_LEN,
            Self::Sha512224 => Sha512224::MESSAGE_DIGEST_LEN,
            Self::Sha512256 => Sha512256::MESSAGE_DIGEST_LEN,
            Self::Sha3224   => Sha3224::MESSAGE_DIGEST_LEN,
            Self::Sha3256   => Sha3256::MESSAGE_DIGEST_LEN,
            Self::Sha3384   => Sha3384::MESSAGE_DIGEST_LEN,
            Self::Sha3512   => Sha3512::MESSAGE_DIGEST_LEN,
        };
    }

    pub fn digest_oneshot(&self, msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Sha224    => Sha224::digest_oneshot(msg, md),
            Self::Sha256    => Sha256::digest_oneshot(msg, md),
            Self::Sha384    => Sha384::digest_oneshot(msg, md),
            Self::Sha512    => Sha512::digest_oneshot(msg, md),
            Self::Sha512224 => Sha512224::digest_oneshot(msg, md),
            Self::Sha512256 => Sha512256::digest_oneshot(msg, md),
            Self::Sha3224   => Sha3224::digest_oneshot(msg, md),
            Self::Sha3256   => Sha3256::digest_oneshot(msg, md),
            Self::Sha3384   => Sha3384::digest_oneshot(msg, md),
            Self::Sha3512   => Sha3512::digest_oneshot(msg, md),
        };
    }

}

impl Hash {

    pub fn new(algo: HashAlgorithm) -> Self {
        return match algo {
            HashAlgorithm::Sha224    => Self::Sha224(Sha224::new()),
            HashAlgorithm::Sha256    => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384    => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512    => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha512224 => Self::Sha512224(Sha512224::new()),
            HashAlgorithm::Sha512256 => Self::Sha512256(Sha512256::new()),
            HashAlgorithm::Sha3224   => Self::Sha3224(Sha3224::new()),
            HashAlgorithm::Sha3256   => Self::Sha3256(Sha3256::new()),
            HashAlgorithm::Sha3384   => Self::Sha3384(Sha3384::new()),
            HashAlgorithm::Sha3512   => Self::Sha3512(Sha3512::new()),
        };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.reset().err(),
            Self::Sha256(v)    => v.reset().err(),
            Self::Sha384(v)    => v.reset().err(),
            Self::Sha512(v)    => v.reset().err(),
            Self::Sha512224(v) => v.reset().err(),
            Self::Sha512256(v) => v.reset().err(),
            Self::Sha3224(v)   => v.reset().err(),
            Self::Sha3256(v)   => v.reset().err(),
            Self::Sha3384(v)   => v.reset().err(),
            Self::Sha3512(v)   => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.update(msg).err(),
            Self::Sha256(v)    => v.update(msg).err(),
            Self::Sha384(v)    => v.update(msg).err(),
            Self::Sha512(v)    => v.update(msg).err(),
            Self::Sha512224(v) => v.update(msg).err(),
            Self::Sha512256(v) => v.update(msg).err(),
            Self::Sha3224(v)   => v.update(msg).err(),
            Self::Sha3256(v)   => v.update(msg).err(),
            Self::Sha3384(v)   => v.update(msg).err(),
            Self::Sha3512(v)   => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {
        return if let Some(e) = match self {
            Self::Sha224(v)    => v.digest(md).err(),
            Self::Sha256(v)    => v.digest(md).err(),
            Self::Sha384(v)    => v.digest(md).err(),
            Self::Sha512(v)    => v.digest(md).err(),
            Self::Sha512224(v) => v.digest(md).err(),
            Self::Sha512256(v) => v.digest(md).err(),
            Self::Sha3224(v)   => v.digest(md).err(),
            Self::Sha3256(v)   => v.digest(md).err(),
            Self::Sha3384(v)   => v.digest(md).err(),
            Self::Sha3512(v)   => v.digest(md).err(),
        } { Err(e) } else { Ok(()) };
    }

}

#[derive(Clone, Copy)]
pub enum MacAlgorithm {
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha3224,
    HmacSha3256,
    HmacSha3384,
    HmacSha3512,
    Poly1305,
}

pub enum Mac {
    HmacSha224(HmacSha224),
    HmacSha256(HmacSha256),
    HmacSha384(HmacSha384),
    HmacSha512(HmacSha512),
    HmacSha3224(HmacSha3224),
    HmacSha3256(HmacSha3256),
    HmacSha3384(HmacSha3384),
    HmacSha3512(HmacSha3512),
    Poly1305(Poly1305),
}

impl MacAlgorithm {

    pub fn mac_len(&self) -> usize {
        return match self {
            Self::HmacSha224  => HmacSha224::MAC_LEN,
            Self::HmacSha256  => HmacSha256::MAC_LEN,
            Self::HmacSha384  => HmacSha384::MAC_LEN,
            Self::HmacSha512  => HmacSha512::MAC_LEN,
            Self::HmacSha3224 => HmacSha3224::MAC_LEN,
            Self::HmacSha3256 => HmacSha3256::MAC_LEN,
            Self::HmacSha3384 => HmacSha3384::MAC_LEN,
            Self::HmacSha3512 => HmacSha3512::MAC_LEN,
            Self::Poly1305    => Poly1305::MAC_LEN,
        };
    }

    pub fn compute_oneshot(&self, key: &[u8], msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha224  => HmacSha224::compute_oneshot(key, msg, md),
            Self::HmacSha256  => HmacSha256::compute_oneshot(key, msg, md),
            Self::HmacSha384  => HmacSha384::compute_oneshot(key, msg, md),
            Self::HmacSha512  => HmacSha512::compute_oneshot(key, msg, md),
            Self::HmacSha3224 => HmacSha3224::compute_oneshot(key, msg, md),
            Self::HmacSha3256 => HmacSha3256::compute_oneshot(key, msg, md),
            Self::HmacSha3384 => HmacSha3384::compute_oneshot(key, msg, md),
            Self::HmacSha3512 => HmacSha3512::compute_oneshot(key, msg, md),
            Self::Poly1305    => Poly1305::compute_oneshot(key, msg, md),
        };
    }

}

impl Mac {

    pub fn new(algo: MacAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            MacAlgorithm::HmacSha224  => Ok(Self::HmacSha224(HmacSha224::new(key)?)),
            MacAlgorithm::HmacSha256  => Ok(Self::HmacSha256(HmacSha256::new(key)?)),
            MacAlgorithm::HmacSha384  => Ok(Self::HmacSha384(HmacSha384::new(key)?)),
            MacAlgorithm::HmacSha512  => Ok(Self::HmacSha512(HmacSha512::new(key)?)),
            MacAlgorithm::HmacSha3224 => Ok(Self::HmacSha3224(HmacSha3224::new(key)?)),
            MacAlgorithm::HmacSha3256 => Ok(Self::HmacSha3256(HmacSha3256::new(key)?)),
            MacAlgorithm::HmacSha3384 => Ok(Self::HmacSha3384(HmacSha3384::new(key)?)),
            MacAlgorithm::HmacSha3512 => Ok(Self::HmacSha3512(HmacSha3512::new(key)?)),
            MacAlgorithm::Poly1305    => Ok(Self::Poly1305(Poly1305::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.rekey(key).err(),
            Self::HmacSha256(v)  => v.rekey(key).err(),
            Self::HmacSha384(v)  => v.rekey(key).err(),
            Self::HmacSha512(v)  => v.rekey(key).err(),
            Self::HmacSha3224(v) => v.rekey(key).err(),
            Self::HmacSha3256(v) => v.rekey(key).err(),
            Self::HmacSha3384(v) => v.rekey(key).err(),
            Self::HmacSha3512(v) => v.rekey(key).err(),
            Self::Poly1305(v)    => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.reset().err(),
            Self::HmacSha256(v)  => v.reset().err(),
            Self::HmacSha384(v)  => v.reset().err(),
            Self::HmacSha512(v)  => v.reset().err(),
            Self::HmacSha3224(v) => v.reset().err(),
            Self::HmacSha3256(v) => v.reset().err(),
            Self::HmacSha3384(v) => v.reset().err(),
            Self::HmacSha3512(v) => v.reset().err(),
            Self::Poly1305(v)    => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha224(v)  => v.update(msg).err(),
            Self::HmacSha256(v)  => v.update(msg).err(),
            Self::HmacSha384(v)  => v.update(msg).err(),
            Self::HmacSha512(v)  => v.update(msg).err(),
            Self::HmacSha3224(v) => v.update(msg).err(),
            Self::HmacSha3256(v) => v.update(msg).err(),
            Self::HmacSha3384(v) => v.update(msg).err(),
            Self::HmacSha3512(v) => v.update(msg).err(),
            Self::Poly1305(v)    => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha224(v)  => v.compute(mac),
            Self::HmacSha256(v)  => v.compute(mac),
            Self::HmacSha384(v)  => v.compute(mac),
            Self::HmacSha512(v)  => v.compute(mac),
            Self::HmacSha3224(v) => v.compute(mac),
            Self::HmacSha3256(v) => v.compute(mac),
            Self::HmacSha3384(v) => v.compute(mac),
            Self::HmacSha3512(v) => v.compute(mac),
            Self::Poly1305(v)    => v.compute(mac),
        };
    }

}

#[derive(Clone, Copy)]
pub enum XofAlgorithm {
    Shake128,
    Shake256,
}

pub enum Xof {
    Shake128(Shake128),
    Shake256(Shake256),
}

impl XofAlgorithm {

    pub fn output_oneshot(&self, msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return match self {
            Self::Shake128 => Shake128::output_oneshot(msg, output, d),
            Self::Shake256 => Shake256::output_oneshot(msg, output, d),
        };
    }

}

impl Xof {

    pub fn new(algo: XofAlgorithm) -> Self {
        return match algo {
            XofAlgorithm::Shake128 => Self::Shake128(Shake128::new()),
            XofAlgorithm::Shake256 => Self::Shake256(Shake256::new()),
        };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Shake128(v) => v.reset().err(),
            Self::Shake256(v) => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Shake128(v) => v.update(msg).err(),
            Self::Shake256(v) => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return match self {
            Self::Shake128(v) => v.output(output, d),
            Self::Shake256(v) => v.output(output, d),
        };
    }

}