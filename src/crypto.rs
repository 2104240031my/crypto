pub mod uint;
pub mod cipher;
pub mod hash;
pub mod dh;
pub mod aes;
pub mod sha2;
pub mod sha3;
pub mod curve25519;

use std::error::Error;
use std::fmt::Display;

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