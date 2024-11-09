use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::Hash;
use crate::crypto::Mac;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;

pub struct HmacSha224 {
    hash_state: Sha224,
    inner: [u8; Sha224::BLOCK_SIZE],
    outer: [u8; Sha224::BLOCK_SIZE + Sha224::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha256 {
    hash_state: Sha256,
    inner: [u8; Sha256::BLOCK_SIZE],
    outer: [u8; Sha256::BLOCK_SIZE + Sha256::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha384 {
    hash_state: Sha384,
    inner: [u8; Sha384::BLOCK_SIZE],
    outer: [u8; Sha384::BLOCK_SIZE + Sha384::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha512 {
    hash_state: Sha512,
    inner: [u8; Sha512::BLOCK_SIZE],
    outer: [u8; Sha512::BLOCK_SIZE + Sha512::MESSAGE_DIGEST_LEN]
}

impl HmacSha224 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha224::new(),
            inner: [0; Sha224::BLOCK_SIZE],
            outer: [0; Sha224::BLOCK_SIZE + Sha224::MESSAGE_DIGEST_LEN],
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha224 {

    const MAC_LEN: usize = HMAC_SHA224_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha224::BLOCK_SIZE {
            Sha224::digest_oneshot(key, &mut self.inner[..Sha224::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha224::BLOCK_SIZE {
            self.outer[i] = self.inner[i] ^ 0x5c;
            self.inner[i] = self.inner[i] ^ 0x36;
        }

        return Ok(self);

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.hash_state.reset()?.update(&self.inner[..])?;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        self.hash_state.update(msg)?;
        return Ok(self);
    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {

        if mac.len() != HMAC_SHA224_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha224::BLOCK_SIZE..])?;
        return Sha224::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha256 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha256::new(),
            inner: [0; Sha256::BLOCK_SIZE],
            outer: [0; Sha256::BLOCK_SIZE + Sha256::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha256 {

    const MAC_LEN: usize = HMAC_SHA256_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha256::BLOCK_SIZE {
            Sha256::digest_oneshot(key, &mut self.inner[..Sha256::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha256::BLOCK_SIZE {
            self.outer[i] = self.inner[i] ^ 0x5c;
            self.inner[i] = self.inner[i] ^ 0x36;
        }

        return Ok(self);

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.hash_state.reset()?.update(&self.inner[..])?;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        self.hash_state.update(msg)?;
        return Ok(self);
    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {

        if mac.len() != HMAC_SHA256_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha256::BLOCK_SIZE..])?;
        return Sha256::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha384 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha384::new(),
            inner: [0; Sha384::BLOCK_SIZE],
            outer: [0; Sha384::BLOCK_SIZE + Sha384::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha384 {

    const MAC_LEN: usize = HMAC_SHA384_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha384::BLOCK_SIZE {
            Sha384::digest_oneshot(key, &mut self.inner[..Sha384::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha384::BLOCK_SIZE {
            self.outer[i] = self.inner[i] ^ 0x5c;
            self.inner[i] = self.inner[i] ^ 0x36;
        }

        return Ok(self);

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.hash_state.reset()?.update(&self.inner[..])?;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        self.hash_state.update(msg)?;
        return Ok(self);
    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {

        if mac.len() != HMAC_SHA384_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha384::BLOCK_SIZE..])?;
        return Sha384::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha512 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha512::new(),
            inner: [0; Sha512::BLOCK_SIZE],
            outer: [0; Sha512::BLOCK_SIZE + Sha512::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha512 {

    const MAC_LEN: usize = HMAC_SHA512_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha512::BLOCK_SIZE {
            Sha512::digest_oneshot(key, &mut self.inner[..Sha512::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha512::BLOCK_SIZE {
            self.outer[i] = self.inner[i] ^ 0x5c;
            self.inner[i] = self.inner[i] ^ 0x36;
        }

        return Ok(self);

    }

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        self.hash_state.reset()?.update(&self.inner[..])?;
        return Ok(self);
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        self.hash_state.update(msg)?;
        return Ok(self);
    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {

        if mac.len() != HMAC_SHA512_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha512::BLOCK_SIZE..])?;
        return Sha512::digest_oneshot(&self.outer[..], mac);

    }

}

const HMAC_SHA224_MAC_LEN: usize = Sha224::MESSAGE_DIGEST_LEN;
const HMAC_SHA256_MAC_LEN: usize = Sha256::MESSAGE_DIGEST_LEN;
const HMAC_SHA384_MAC_LEN: usize = Sha384::MESSAGE_DIGEST_LEN;
const HMAC_SHA512_MAC_LEN: usize = Sha512::MESSAGE_DIGEST_LEN;