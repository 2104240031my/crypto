use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::DigitalSignature;
use crate::crypto::DigitalSignatureSigner;
use crate::crypto::DigitalSignatureVerifier;
use crate::crypto::Hash;
use crate::crypto::ec25519::Ec25519Uint;
use crate::crypto::ec25519::Edwards25519Point;
use crate::crypto::ec25519::B;
use crate::crypto::ec25519::Q;
use crate::crypto::sha2::Sha512;

pub struct Ed25519 {
    s: Ed25519Signer,
    v: Ed25519Verifier
}

pub struct Ed25519Signer {
    priv_key: [u8; 32]
}

pub struct Ed25519Verifier {
    pub_key: [u8; 32]
}

impl Ed25519 {

    pub const PRIVATE_KEY_LEN: usize = ED25519_PRIVATE_KEY_LEN;
    pub const PUBLIC_KEY_LEN: usize  = ED25519_PUBLIC_KEY_LEN;
    pub const SIGNATURE_LEN: usize   = ED25519_SIGNATURE_LEN;

    pub fn new(priv_key: &[u8]) -> Result<Self, CryptoError> {

        let mut pub_key: [u8; 32] = [0; 32];
        Ed25519Signer::compute_public_key_oneshot(priv_key, &mut pub_key[..])?;

        return Ok(Self{
            s: Ed25519Signer::new(priv_key)?,
            v: Ed25519Verifier::new(&pub_key[..])?,
        });

    }

}

impl DigitalSignature for Ed25519 {

    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return Ed25519Signer::compute_public_key_oneshot(priv_key, pub_key);
    }

    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return Ed25519Signer::sign_oneshot(priv_key, msg, signature);
    }

    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return Ed25519Verifier::verify_oneshot(pub_key, msg, signature);
    }

    fn rekey(&mut self, priv_key: &[u8]) -> Result<(), CryptoError> {
        self.s.rekey(priv_key)?;
        return self.s.compute_public_key(&mut self.v.pub_key[..]);
    }

    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return self.s.compute_public_key(pub_key);
    }

    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return self.s.sign(msg, signature);
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return self.v.verify(msg, signature);
    }

}

impl Ed25519Signer {

    pub fn new(priv_key: &[u8]) -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            priv_key: [0; 32]
        };

        v.rekey(priv_key);
        return Ok(v);

    }

}

impl DigitalSignatureSigner for Ed25519Signer {

    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() < ED25519_PRIVATE_KEY_LEN || pub_key.len() < ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        return ed25519_compute_public_key(priv_key, pub_key);

    }

    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() < ED25519_PRIVATE_KEY_LEN || signature.len() < ED25519_SIGNATURE_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        return ed25519_sign(priv_key, msg, signature);

    }

    fn rekey(&mut self, priv_key: &[u8]) -> Result<(), CryptoError> {

        if priv_key.len() < ED25519_PRIVATE_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        self.priv_key.copy_from_slice(&priv_key[..32]);
        return Ok(());

    }

    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return ed25519_compute_public_key(&self.priv_key[..], pub_key);
    }

    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return ed25519_sign(&self.priv_key[..], msg, signature);
    }

}

impl Ed25519Verifier {

    pub fn new(pub_key: &[u8]) -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            pub_key: [0; 32]
        };

        v.rekey(pub_key);
        return Ok(v);

    }

}

impl DigitalSignatureVerifier for Ed25519Verifier {

    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {

        if pub_key.len() < ED25519_PUBLIC_KEY_LEN || signature.len() < ED25519_SIGNATURE_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        return ed25519_verify(pub_key, msg, signature);

    }

    fn rekey(&mut self, pub_key: &[u8]) -> Result<(), CryptoError> {

        if pub_key.len() < ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        self.pub_key.copy_from_slice(&pub_key[..32]);
        return Ok(());

    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return ed25519_verify(&self.pub_key[..], msg, signature);
    }

}

const ED25519_PRIVATE_KEY_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize  = 32;
const ED25519_SIGNATURE_LEN: usize   = 64;

fn ed25519_compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {

    let mut h: [u8; 64] = [0; 64];
    Sha512::digest_oneshot(&priv_key[..32], &mut h[..])?;
    let s: Ec25519Uint = Ec25519Uint::try_from_bytes_as_scalar(&h[..32])?;

    let mut a: Edwards25519Point = Edwards25519Point::new();
    Edwards25519Point::scalar_mul(&mut a, &B, &s);
    a.try_into_bytes(pub_key);

    return Ok(());

}

fn ed25519_sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {

    let mut p: Edwards25519Point = Edwards25519Point::new();
    let mut sha512: Sha512 = Sha512::new();
    let mut b: [u8; 64] = [0; 64];

    Sha512::digest_oneshot(&priv_key[..32], &mut b[..]);
    let s: Ec25519Uint = Ec25519Uint::try_from_bytes_as_scalar(&b[..32])?;

    sha512.reset();
    sha512.update(&b[32..]);
    sha512.update(msg);
    sha512.digest(&mut b[..]);
    let r: Ec25519Uint = Ec25519Uint::try_from_sha512_digest(&b[..])?;

    Edwards25519Point::scalar_mul(&mut p, &B, &r);
    p.try_into_bytes(&mut signature[..32]);

    Edwards25519Point::scalar_mul(&mut p, &B, &s);
    p.try_into_bytes(&mut b[..32]);

    sha512.reset();
    sha512.update(&signature[..32]);
    sha512.update(&b[..32]);
    sha512.update(msg);
    sha512.digest(&mut b[..]);
    let mut k: Ec25519Uint = Ec25519Uint::try_from_sha512_digest(&b[..])?;
    Ec25519Uint::gmul_assign_mod_order(&mut k, &s);
    Ec25519Uint::gadd_assign_mod_order(&mut k, &r);

    k.try_into_bytes(&mut signature[32..64]);
    return Ok(());

}

fn ed25519_verify(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {

    let mut sha512: Sha512 = Sha512::new();
    let mut b: [u8; 64] = [0; 64];

    let mut a: Edwards25519Point = Edwards25519Point::try_from_bytes(&pub_key[..32])?;
    let mut r: Edwards25519Point = Edwards25519Point::try_from_bytes(&signature[..32])?;
    let s: Ec25519Uint = Ec25519Uint::try_from_bytes(&signature[32..])?;

    if !Ec25519Uint::lt(&s, &Q) {
        return Err(CryptoError::new(CryptoErrorCode::VerifFailed));
    }

    sha512.reset();
    sha512.update(&signature[..32]);
    sha512.update(&pub_key[..32]);
    sha512.update(msg);
    sha512.digest(&mut b[..]);
    let k: Ec25519Uint = Ec25519Uint::try_from_sha512_digest(&b[..])?;
    Edwards25519Point::scalar_mul_assign(&mut a, &k);
    Edwards25519Point::add_assign(&mut a, &r);
    Edwards25519Point::scalar_mul(&mut r, &B, &s);

    return if Edwards25519Point::eq(&r, &a) {
        Ok(true)
    } else {
        Err(CryptoError::new(CryptoErrorCode::VerifFailed))
    };

}

impl Ec25519Uint {

    fn try_from_sha512_digest(md: &[u8]) -> Result<Self, CryptoError> {

        if md.len() < 64 {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let buf: [u32; 16] = [
            u32::from_le_bytes(md[60..64].try_into().unwrap()),
            u32::from_le_bytes(md[56..60].try_into().unwrap()),
            u32::from_le_bytes(md[52..56].try_into().unwrap()),
            u32::from_le_bytes(md[48..52].try_into().unwrap()),
            u32::from_le_bytes(md[44..48].try_into().unwrap()),
            u32::from_le_bytes(md[40..44].try_into().unwrap()),
            u32::from_le_bytes(md[36..40].try_into().unwrap()),
            u32::from_le_bytes(md[32..36].try_into().unwrap()),
            u32::from_le_bytes(md[28..32].try_into().unwrap()),
            u32::from_le_bytes(md[24..28].try_into().unwrap()),
            u32::from_le_bytes(md[20..24].try_into().unwrap()),
            u32::from_le_bytes(md[16..20].try_into().unwrap()),
            u32::from_le_bytes(md[12..16].try_into().unwrap()),
            u32::from_le_bytes(md[ 8..12].try_into().unwrap()),
            u32::from_le_bytes(md[ 4.. 8].try_into().unwrap()),
            u32::from_le_bytes(md[ 0.. 4].try_into().unwrap())
        ];

        let mut v: Self = Self::new();
        Self::mod_order(&mut v, &buf[..]);

        return Ok(v);

    }

}