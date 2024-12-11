use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::feature::BlockHash;
use crate::crypto::feature::Hash;
use crate::crypto::feature::Hmac;
use crate::crypto::feature::Mac;

pub struct HmacSha224 {
    hash_state: Sha224,
    inner: [u8; <Self as Hmac>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as Hmac>::HASH_BLOCK_SIZE + <Self as Hmac>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha256 {
    hash_state: Sha256,
    inner: [u8; <Self as Hmac>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as Hmac>::HASH_BLOCK_SIZE + <Self as Hmac>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha384 {
    hash_state: Sha384,
    inner: [u8; <Self as Hmac>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as Hmac>::HASH_BLOCK_SIZE + <Self as Hmac>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha512 {
    hash_state: Sha512,
    inner: [u8; <Self as Hmac>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as Hmac>::HASH_BLOCK_SIZE + <Self as Hmac>::HASH_MESSAGE_DIGEST_LEN]
}

impl HmacSha224 {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha224::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN],
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }
}

impl Hmac for HmacSha224 {
    const HASH_BLOCK_SIZE: usize         = Sha224::BLOCK_SIZE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha224::MESSAGE_DIGEST_LEN;
}

impl Mac for HmacSha224 {

    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha224::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Self::HASH_BLOCK_SIZE {
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

        if mac.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Self::HASH_BLOCK_SIZE..])?;
        return Sha224::digest_oneshot(&self.outer[..], mac);

    }

}

impl Drop for HmacSha224 {
    fn drop(&mut self) {
        self.inner.fill(0);
        self.outer.fill(0);
    }
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha256::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }
}

impl Hmac for HmacSha256 {
    const HASH_BLOCK_SIZE: usize         = Sha256::BLOCK_SIZE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha256::MESSAGE_DIGEST_LEN;
}

impl Mac for HmacSha256 {

    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha256::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Self::HASH_BLOCK_SIZE {
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

        if mac.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Self::HASH_BLOCK_SIZE..])?;
        return Sha256::digest_oneshot(&self.outer[..], mac);

    }

}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        self.inner.fill(0);
        self.outer.fill(0);
    }
}

impl HmacSha384 {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha384::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }
}

impl Hmac for HmacSha384 {
    const HASH_BLOCK_SIZE: usize         = Sha384::BLOCK_SIZE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha384::MESSAGE_DIGEST_LEN;
}

impl Mac for HmacSha384 {

    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha384::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Self::HASH_BLOCK_SIZE {
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

        if mac.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Self::HASH_BLOCK_SIZE..])?;
        return Sha384::digest_oneshot(&self.outer[..], mac);

    }

}

impl Drop for HmacSha384 {
    fn drop(&mut self) {
        self.inner.fill(0);
        self.outer.fill(0);
    }
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha512::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }
}

impl Hmac for HmacSha512 {
    const HASH_BLOCK_SIZE: usize         = Sha512::BLOCK_SIZE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha512::MESSAGE_DIGEST_LEN;
}

impl Mac for HmacSha512 {

    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha512::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Self::HASH_BLOCK_SIZE {
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

        if mac.len() != Self::MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Self::HASH_BLOCK_SIZE..])?;
        return Sha512::digest_oneshot(&self.outer[..], mac);

    }

}

impl Drop for HmacSha512 {
    fn drop(&mut self) {
        self.inner.fill(0);
        self.outer.fill(0);
    }
}