pub mod aes;
pub mod blockcipher;
pub mod sha2;
pub mod sha3;
pub mod x25519;
pub mod ed25519;
mod ec25519;

use std::error::Error;
use std::fmt::Display;

pub trait BlockCipher {
    fn encrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn decrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
}

pub trait Hash {
    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Option<CryptoError>;
    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError>;
}

pub trait DiffieHellman {
    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError>;
}

pub trait DigitalSignature {
    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Option<CryptoError>;
    fn verify(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Option<CryptoError>;
}

#[derive(Debug)]
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

}