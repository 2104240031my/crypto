use crate::crypto::error::CryptoError;
use crate::crypto::sha3::Shake128;
use crate::crypto::sha3::Shake256;

pub trait XofStdFeature: XofStdStaticFn + XofStdInstanceFn {}

pub trait XofStdStaticFn {
    fn output_oneshot(msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError>;
}

pub trait XofStdInstanceFn {
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError>;
}

pub enum XofAlgorithm {
    Null,
    Shake128,
    Shake256,
}

pub enum Xof {
    Null(()),
    Shake128(Shake128),
    Shake256(Shake256),
}

impl Xof {

    pub fn new(algo: XofAlgorithm) -> Self {
        return match algo {
            XofAlgorithm::Null     => Self::Null(()),
            XofAlgorithm::Shake128 => Self::Shake128(Shake128::new()),
            XofAlgorithm::Shake256 => Self::Shake256(Shake256::new()),
        };
    }

    pub fn output_oneshot(algo: XofAlgorithm, msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return match self {
            XofAlgorithm::Null     => Ok(()),
            XofAlgorithm::Shake128 => Shake128::output_oneshot(msg, output, d),
            XofAlgorithm::Shake256 => Shake256::output_oneshot(msg, output, d),
        };
    }

}

impl XofStdInstanceFn for Xof {

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Null(())    => None,
            Self::Shake128(v) => v.reset().err(),
            Self::Shake256(v) => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Shake128(v) => v.update(msg).err(),
            Self::Shake256(v) => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        return if let Some(e) = match self {
            Self::Shake128(v) => v.output(output, d).err(),
            Self::Shake256(v) => v.output(output, d).err(),
        } { Err(e) } else { Ok(()) };
    }

}