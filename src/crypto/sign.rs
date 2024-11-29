use crate::crypto::error::CryptoError;

pub trait DigitalSignatureSignerStdFeature:
    DigitalSignatureSignerStdConst +
    DigitalSignatureSignerStdStaticFn +
    DigitalSignatureSignerStdInstanceFn {}

pub trait DigitalSignatureSignerStdConst {
    const PRIVATE_KEY_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
}

pub trait DigitalSignatureSignerStdStaticFn {
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignatureSignerStdInstanceFn {
    fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignatureVerifierStdFeature:
    DigitalSignatureVerifierStdConst +
    DigitalSignatureVerifierStdStaticFn +
    DigitalSignatureVerifierStdInstanceFn {}

pub trait DigitalSignatureVerifierStdConst {
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
}

pub trait DigitalSignatureVerifierStdStaticFn {
    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

pub trait DigitalSignatureVerifierStdInstanceFn {
    fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}