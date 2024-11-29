use crate::crypto::error::CryptoError;

pub trait DiffieHellmanStdFeature: DiffieHellmanStdConst + DiffieHellmanStdStaticFn {}

pub trait DiffieHellmanStdConst {
    const PRIVATE_KEY_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SHARED_SECRET_LEN: usize;
}

pub trait DiffieHellmanStdStaticFn {
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_shared_secret_oneshot(priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError>;
}