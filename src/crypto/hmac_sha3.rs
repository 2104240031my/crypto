use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::Hash;
use crate::crypto::Mac;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;

pub struct HmacSha3224 {
    hash_state: Sha3224,
    inner: [u8; Sha3224::BLOCK_SIZE],
    outer: [u8; Sha3224::BLOCK_SIZE + Sha3224::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3256 {
    hash_state: Sha3256,
    inner: [u8; Sha3256::BLOCK_SIZE],
    outer: [u8; Sha3256::BLOCK_SIZE + Sha3256::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3384 {
    hash_state: Sha3384,
    inner: [u8; Sha3384::BLOCK_SIZE],
    outer: [u8; Sha3384::BLOCK_SIZE + Sha3384::MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3512 {
    hash_state: Sha3512,
    inner: [u8; Sha3512::BLOCK_SIZE],
    outer: [u8; Sha3512::BLOCK_SIZE + Sha3512::MESSAGE_DIGEST_LEN]
}

impl HmacSha3224 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3224::new(),
            inner: [0; Sha3224::BLOCK_SIZE],
            outer: [0; Sha3224::BLOCK_SIZE + Sha3224::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha3224 {

    const MAC_LEN: usize = HMAC_SHA3_224_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha3224::BLOCK_SIZE {
            Sha3224::digest_oneshot(key, &mut self.inner[..Sha3224::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha3224::BLOCK_SIZE {
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

        if mac.len() != HMAC_SHA3_224_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha3224::BLOCK_SIZE..])?;
        return Sha3224::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3256 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3256::new(),
            inner: [0; Sha3256::BLOCK_SIZE],
            outer: [0; Sha3256::BLOCK_SIZE + Sha3256::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha3256 {

    const MAC_LEN: usize = HMAC_SHA3_256_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha3256::BLOCK_SIZE {
            Sha3256::digest_oneshot(key, &mut self.inner[..Sha3256::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha3256::BLOCK_SIZE {
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

        if mac.len() != HMAC_SHA3_256_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha3256::BLOCK_SIZE..])?;
        return Sha3256::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3384 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3384::new(),
            inner: [0; Sha3384::BLOCK_SIZE],
            outer: [0; Sha3384::BLOCK_SIZE + Sha3384::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha3384 {

    const MAC_LEN: usize = HMAC_SHA3_384_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha3384::BLOCK_SIZE {
            Sha3384::digest_oneshot(key, &mut self.inner[..Sha3384::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha3384::BLOCK_SIZE {
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

        if mac.len() != HMAC_SHA3_384_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha3384::BLOCK_SIZE..])?;
        return Sha3384::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3512 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3512::new(),
            inner: [0; Sha3512::BLOCK_SIZE],
            outer: [0; Sha3512::BLOCK_SIZE + Sha3512::MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl Mac for HmacSha3512 {

    const MAC_LEN: usize = HMAC_SHA3_512_MAC_LEN;

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Sha3512::BLOCK_SIZE {
            Sha3512::digest_oneshot(key, &mut self.inner[..Sha3512::MESSAGE_DIGEST_LEN])?;
        } else {
            self.inner[..key.len()].copy_from_slice(key);
        }

        for i in 0..Sha3512::BLOCK_SIZE {
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

        if mac.len() != HMAC_SHA3_512_MAC_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        self.hash_state.digest(&mut self.outer[Sha3512::BLOCK_SIZE..])?;
        return Sha3512::digest_oneshot(&self.outer[..], mac);

    }

}

const HMAC_SHA3_224_MAC_LEN: usize = Sha3224::MESSAGE_DIGEST_LEN;
const HMAC_SHA3_256_MAC_LEN: usize = Sha3256::MESSAGE_DIGEST_LEN;
const HMAC_SHA3_384_MAC_LEN: usize = Sha3384::MESSAGE_DIGEST_LEN;
const HMAC_SHA3_512_MAC_LEN: usize = Sha3512::MESSAGE_DIGEST_LEN;