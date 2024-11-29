use crate::crypto::curve_over_fp25519::Fp25519Uint;
use crate::crypto::curve_over_fp25519::Edwards25519Point;
use crate::crypto::curve_over_fp25519::B;
use crate::crypto::curve_over_fp25519::Q;
use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::feature::Hash;
use crate::crypto::feature::DigitalSignatureSigner;
use crate::crypto::feature::DigitalSignatureVerifier;
use crate::crypto::sha2::Sha512;

pub struct Ed25519;

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

    pub fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return Ed25519Signer::compute_public_key_oneshot(priv_key, pub_key);
    }

    pub fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return Ed25519Signer::sign_oneshot(priv_key, msg, signature);
    }

    pub fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return Ed25519Verifier::verify_oneshot(pub_key, msg, signature);
    }

}

impl Ed25519Signer {

    pub fn new(priv_key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{ priv_key: [0; 32] };
        v.rekey(priv_key)?;
        return Ok(v);
    }

}

impl DigitalSignatureSigner for Ed25519Signer {

    const PRIVATE_KEY_LEN: usize = ED25519_PRIVATE_KEY_LEN;
    const PUBLIC_KEY_LEN: usize  = ED25519_PUBLIC_KEY_LEN;
    const SIGNATURE_LEN: usize   = ED25519_SIGNATURE_LEN;

    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() != ED25519_PRIVATE_KEY_LEN || pub_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        return ed25519_compute_public_key(priv_key, pub_key);

    }

    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() != ED25519_PRIVATE_KEY_LEN || signature.len() != ED25519_SIGNATURE_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        return ed25519_sign(priv_key, msg, signature);

    }

    fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError> {

        if priv_key.len() != ED25519_PRIVATE_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.priv_key.copy_from_slice(&priv_key[..32]);
        return Ok(self);

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
        let mut v: Self = Self{ pub_key: [0; 32] };
        v.rekey(pub_key)?;
        return Ok(v);
    }

}

impl DigitalSignatureVerifier for Ed25519Verifier {

    const PUBLIC_KEY_LEN: usize  = ED25519_PUBLIC_KEY_LEN;
    const SIGNATURE_LEN: usize   = ED25519_SIGNATURE_LEN;

    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {

        if pub_key.len() != ED25519_PUBLIC_KEY_LEN || signature.len() != ED25519_SIGNATURE_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        return ed25519_verify(pub_key, msg, signature);

    }

    fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError> {

        if pub_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.pub_key.copy_from_slice(&pub_key[..32]);
        return Ok(self);

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
    let s: Fp25519Uint = Fp25519Uint::try_from_bytes_as_scalar(&h[..32])?;

    let mut a: Edwards25519Point = Edwards25519Point::new();
    Edwards25519Point::scalar_mul(&mut a, &B, &s);
    a.try_into_bytes(pub_key)?;

    return Ok(());

}

fn ed25519_sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {

    let mut p: Edwards25519Point = Edwards25519Point::new();
    let mut sha512: Sha512 = Sha512::new();
    let mut b: [u8; 64] = [0; 64];

    Sha512::digest_oneshot(&priv_key[..32], &mut b[..])?;
    let s: Fp25519Uint = Fp25519Uint::try_from_bytes_as_scalar(&b[..32])?;

    sha512.reset()?.update(&b[32..])?.update(msg)?.digest(&mut b[..])?;
    let r: Fp25519Uint = Fp25519Uint::try_from_sha512_digest(&b[..])?;

    Edwards25519Point::scalar_mul(&mut p, &B, &r);
    p.try_into_bytes(&mut signature[..32])?;

    Edwards25519Point::scalar_mul(&mut p, &B, &s);
    p.try_into_bytes(&mut b[..32])?;

    sha512.reset()?.update(&signature[..32])?.update(&b[..32])?.update(msg)?.digest(&mut b[..])?;
    let mut k: Fp25519Uint = Fp25519Uint::try_from_sha512_digest(&b[..])?;
    Fp25519Uint::gmul_assign_mod_order(&mut k, &s);
    Fp25519Uint::gadd_assign_mod_order(&mut k, &r);

    k.try_into_bytes(&mut signature[32..64])?;
    return Ok(());

}

fn ed25519_verify(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {

    let mut sha512: Sha512 = Sha512::new();
    let mut b: [u8; 64] = [0; 64];

    let mut a: Edwards25519Point = Edwards25519Point::try_from_bytes(&pub_key[..32])?;
    let mut r: Edwards25519Point = Edwards25519Point::try_from_bytes(&signature[..32])?;
    let s: Fp25519Uint = Fp25519Uint::try_from_bytes(&signature[32..])?;

    if !Fp25519Uint::lt(&s, &Q) {
        return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
    }

    sha512.reset()?.update(&signature[..32])?.update(&pub_key[..32])?.update(msg)?.digest(&mut b[..])?;
    let k: Fp25519Uint = Fp25519Uint::try_from_sha512_digest(&b[..])?;
    Edwards25519Point::scalar_mul_assign(&mut a, &k);
    Edwards25519Point::add_assign(&mut a, &r);
    Edwards25519Point::scalar_mul(&mut r, &B, &s);

    return if Edwards25519Point::eq(&r, &a) {
        Ok(true)
    } else {
        Err(CryptoError::new(CryptoErrorCode::VerificationFailed))
    };

}

impl Fp25519Uint {

    fn try_from_sha512_digest(d: &[u8]) -> Result<Self, CryptoError> {

        if d.len() != 64 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let buf: [u32; 16] = [
            ((d[63] as u32) << 24) | ((d[62] as u32) << 16) | ((d[61] as u32) << 8) | (d[60] as u32),
            ((d[59] as u32) << 24) | ((d[58] as u32) << 16) | ((d[57] as u32) << 8) | (d[56] as u32),
            ((d[55] as u32) << 24) | ((d[54] as u32) << 16) | ((d[53] as u32) << 8) | (d[52] as u32),
            ((d[51] as u32) << 24) | ((d[50] as u32) << 16) | ((d[49] as u32) << 8) | (d[48] as u32),
            ((d[47] as u32) << 24) | ((d[46] as u32) << 16) | ((d[45] as u32) << 8) | (d[44] as u32),
            ((d[43] as u32) << 24) | ((d[42] as u32) << 16) | ((d[41] as u32) << 8) | (d[40] as u32),
            ((d[39] as u32) << 24) | ((d[38] as u32) << 16) | ((d[37] as u32) << 8) | (d[36] as u32),
            ((d[35] as u32) << 24) | ((d[34] as u32) << 16) | ((d[33] as u32) << 8) | (d[32] as u32),
            ((d[31] as u32) << 24) | ((d[30] as u32) << 16) | ((d[29] as u32) << 8) | (d[28] as u32),
            ((d[27] as u32) << 24) | ((d[26] as u32) << 16) | ((d[25] as u32) << 8) | (d[24] as u32),
            ((d[23] as u32) << 24) | ((d[22] as u32) << 16) | ((d[21] as u32) << 8) | (d[20] as u32),
            ((d[19] as u32) << 24) | ((d[18] as u32) << 16) | ((d[17] as u32) << 8) | (d[16] as u32),
            ((d[15] as u32) << 24) | ((d[14] as u32) << 16) | ((d[13] as u32) << 8) | (d[12] as u32),
            ((d[11] as u32) << 24) | ((d[10] as u32) << 16) | ((d[ 9] as u32) << 8) | (d[ 8] as u32),
            ((d[ 7] as u32) << 24) | ((d[ 6] as u32) << 16) | ((d[ 5] as u32) << 8) | (d[ 4] as u32),
            ((d[ 3] as u32) << 24) | ((d[ 2] as u32) << 16) | ((d[ 1] as u32) << 8) | (d[ 0] as u32)
        ];

        let mut v: Self = Self::new();
        Self::mod_order(&mut v, &buf[..]);

        return Ok(v);

    }

}