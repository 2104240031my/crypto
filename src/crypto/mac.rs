use crate::crypto::error::CryptoError;

pub trait MacStdFeature: MacStdConst + MacStdStaticFn + MacStdInstanceFn {}

pub trait MacStdConst {
    const MAC_LEN: usize;
}

pub trait MacStdStaticFn {
    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait MacStdInstanceFn {
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError>;
}