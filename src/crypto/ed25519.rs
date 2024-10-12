use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::DigitalSignature;
use crate::crypto::ec25519::Ec25519Uint;
use crate::crypto::ec25519::Edwards25519Point;
use crate::crypto::ec25519::D;
use crate::crypto::ec25519::B;

pub struct Ed25519 {}

pub const ED25519_PRIVATE_KEY_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize  = 32;
pub const ED25519_SIGNATURE_LEN: usize   = 64;

impl DigitalSignature for Ed25519 {

    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError> {
        return None;
    }

    fn sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Option<CryptoError> {
        return None;
    }

    fn verify(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Option<CryptoError> {
        return None;
    }

}

impl Ec25519Uint {

    fn try_from_sha512_digest(md: &[u8]) -> Result<Self, CryptoError> {

        if md.len() < 64 {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut buf: [u32; 16] = [
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

// [*1] https://www.rfc-editor.org/rfc/rfc8032.html section-5.1, section-5.1.6, section-2
// [*2] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3002-2020.pdf
// [*3] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf
// [*4] https://github.com/golang/go/blob/master/src/crypto/ed25519/ed25519.go
// [*5] https://cr.yp.to/bib/2003/joye-ladder.pdf
// [*6] https://dspace.jaist.ac.jp/dspace/bitstream/10119/9146/7/paper.pdf

// - 拡張射影座標系について [*3] pp17
