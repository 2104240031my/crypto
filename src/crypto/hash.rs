use crate::crypto::CryptoError;

pub trait Hash {
    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError>;
    fn update(&mut self, bytes: &[u8]) -> Option<CryptoError>;
    fn digest(&mut self, digest: &mut [u8]) -> Option<CryptoError>;
}