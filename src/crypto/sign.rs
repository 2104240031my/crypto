use crate::crypto::CryptoError;

pub trait Sign {
    fn sign(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn verify(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError>;
}