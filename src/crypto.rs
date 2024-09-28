pub mod aes;
pub mod sha2;
pub mod sha3;
pub mod x25519;
pub mod ed25519;

use std::error::Error;
use std::fmt::Display;

pub trait BlockCipher {
    fn encrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn decrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
}

pub trait Hash {
    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError>;
    fn update(&mut self, bytes: &[u8]) -> Option<CryptoError>;
    fn digest(&mut self, digest: &mut [u8]) -> Option<CryptoError>;
}

pub trait Dh {
    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError>;
}

pub trait Sign {
    fn sign(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn verify(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError>;
}

#[derive(Debug)]
pub struct CryptoError {
    err_msg: &'static str
}

impl Error for CryptoError {}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto error.")
    }
}

impl CryptoError {
    pub fn new(err_msg: &'static str) -> Self {
        return Self{ err_msg: err_msg };
    }
}