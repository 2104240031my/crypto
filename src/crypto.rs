#[allow(dead_code)]
pub mod aes;

#[allow(dead_code)]
pub mod block_cipher_mode;

#[allow(dead_code)]
pub mod sha2;

#[allow(dead_code)]
pub mod sha3;

#[allow(dead_code)]
pub mod hmac_sha2;

#[allow(dead_code)]
pub mod hmac_sha3;

#[allow(dead_code)]
pub mod x25519;

#[allow(dead_code)]
pub mod ed25519;

#[allow(dead_code)]
mod ec25519;

use std::marker::Copy;
use std::clone::Clone;
use std::error::Error;
use std::fmt::Display;

pub trait BlockCipher {
    fn rekey(&mut self, key: &[u8]) -> Result<(), CryptoError>;
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Result<(), CryptoError>;
    fn encrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn decrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
}

pub trait BlockCipher128: BlockCipher {
    const BLOCK_SIZE: usize;
}

pub trait Hash {
    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait Mac {
    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError>;
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DiffieHellman {
    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignature {
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    fn rekey(&mut self, priv_key: &[u8]) -> Result<(), CryptoError>;
    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

pub trait DigitalSignatureSigner {
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
    fn rekey(&mut self, priv_key: &[u8]) -> Result<(), CryptoError>;
    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignatureVerifier {
    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    fn rekey(&mut self, pub_key: &[u8]) -> Result<(), CryptoError>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

#[derive(Debug, Copy, Clone)]
pub enum CryptoErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    UnsupportedAlgorithm,
    BufferTooShort,
    VerifFailed,

}

#[derive(Debug)]
pub struct CryptoError {
    err_code: CryptoErrorCode
}

impl Error for CryptoError {}

impl Display for CryptoError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[crypto error]: {}", match &self.err_code {
            CryptoErrorCode::Unknown              => "unknown",
            CryptoErrorCode::IllegalArgument      => "illegal argument",
            CryptoErrorCode::UnsupportedAlgorithm => "unsupported algorithm",
            CryptoErrorCode::BufferTooShort       => "buffer too short",
            CryptoErrorCode::VerifFailed          => "verif failed",
        })
    }

}

impl CryptoError {

    pub fn new(err_code: CryptoErrorCode) -> Self {
        return Self{
            err_code: err_code,
        };
    }

    pub fn err_code(&self) -> CryptoErrorCode {
        return self.err_code;
    }

}