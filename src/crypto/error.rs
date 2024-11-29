use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum CryptoErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    UnsupportedAlgorithm,
    BufferLengthIncorrect,
    BufferLengthIsNotMultipleOfBlockSize,
    CounterOverwrapped,
    VerificationFailed

}

impl Clone for CryptoErrorCode {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for CryptoErrorCode {}

#[derive(Debug)]
pub struct CryptoError {
    err_code: CryptoErrorCode
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

impl Display for CryptoError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "CryptoError: {}", match &self.err_code {
            CryptoErrorCode::Unknown                              => "unknown",
            CryptoErrorCode::IllegalArgument                      => "illegal argument",
            CryptoErrorCode::UnsupportedAlgorithm                 => "unsupported algorithm",
            CryptoErrorCode::BufferLengthIncorrect                => "buffer length incorrect",
            CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize => "buffer length is not multiple of block size",
            CryptoErrorCode::CounterOverwrapped                   => "counter overwrapped",
            CryptoErrorCode::VerificationFailed                   => "verification failed"
        });
    }

}

impl Error for CryptoError {}