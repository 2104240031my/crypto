use crate::crypto::error::CryptoError;

pub trait StreamCipherStdFeature: StreamCipherStdConst + StreamCipherStdInstanceFn {}

pub trait StreamCipherStdConst {
    const KEY_LEN: usize;
}

pub trait StreamCipherStdInstanceFn {
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn encrypt_or_decrypt(&mut self, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
}
