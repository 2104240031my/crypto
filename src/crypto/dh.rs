use crate::crypto::CryptoError;

pub trait Dh {
    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError>;
    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError>;
}