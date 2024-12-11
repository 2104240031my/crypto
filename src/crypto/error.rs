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
    VerificationFailed,
    RandomGenerationFailed,
    ReseedRequired,

}

impl CryptoErrorCode {

    pub fn to_str(&self) -> &str {
        return match self {
            Self::Unknown                              => "unknown",
            Self::IllegalArgument                      => "illegal argument",
            Self::UnsupportedAlgorithm                 => "unsupported algorithm",
            Self::BufferLengthIncorrect                => "buffer length incorrect",
            Self::BufferLengthIsNotMultipleOfBlockSize => "buffer length is not multiple of block size",
            Self::CounterOverwrapped                   => "counter overwrapped",
            Self::VerificationFailed                   => "verification failed",
            Self::RandomGenerationFailed               => "random generation failed",
            Self::ReseedRequired                       => "reseed required",
        };
    }

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
        return Self{ err_code: err_code };
    }

    pub fn err_code(&self) -> CryptoErrorCode {
        return self.err_code;
    }

}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "CryptoError: {}", self.err_code.to_str());
    }
}

impl std::error::Error for CryptoError {}