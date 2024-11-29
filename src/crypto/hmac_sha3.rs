use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::hash::HashStdConst;
use crate::crypto::hash::HashStdStaticFn;
use crate::crypto::hash::HashStdInstanceFn;
use crate::crypto::hmac::HmacMacStdFeature;
use crate::crypto::hmac::HmacMacStdConst;
use crate::crypto::hmac::HmacMacStdStaticFn;
use crate::crypto::hmac::HmacMacStdInstanceFn;
use crate::crypto::mac::MacStdFeature;
use crate::crypto::mac::MacStdConst;
use crate::crypto::mac::MacStdStaticFn;
use crate::crypto::mac::MacStdInstanceFn;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;

pub struct HmacSha3224 {
    hash_state: Sha3224,
    inner: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE + <Self as HmacStdConst>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3256 {
    hash_state: Sha3256,
    inner: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE + <Self as HmacStdConst>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3384 {
    hash_state: Sha3384,
    inner: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE + <Self as HmacStdConst>::HASH_MESSAGE_DIGEST_LEN]
}

pub struct HmacSha3512 {
    hash_state: Sha3512,
    inner: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE],
    outer: [u8; <Self as HmacStdConst>::HASH_BLOCK_SIZE + <Self as HmacStdConst>::HASH_MESSAGE_DIGEST_LEN]
}

impl HmacSha3224 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3224::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl HmacStdFeature for HmacSha3224 {}

impl HmacStdConst for HmacSha3224 {
    const HASH_BLOCK_SIZE: usize = Sha3224::RATE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha3224::MESSAGE_DIGEST_LEN;
}

impl HmacStdStaticFn for HmacSha3224 {}

impl HmacStdInstanceFn for HmacSha3224 {}

impl MacStdFeature for HmacSha3224 {}

impl MacStdConst for HmacSha3224 {
    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;
}

impl MacStdStaticFn for HmacSha3224 {

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

}

impl MacStdInstanceFn for HmacSha3224 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha3224::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
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
        return Sha3224::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3256 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3256::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl HmacStdFeature for HmacSha3256 {}

impl HmacStdConst for HmacSha3256 {
    const HASH_BLOCK_SIZE: usize = Sha3256::RATE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha3256::MESSAGE_DIGEST_LEN;
}

impl HmacStdStaticFn for HmacSha3256 {}

impl HmacStdInstanceFn for HmacSha3256 {}

impl MacStdFeature for HmacSha3256 {}

impl MacStdConst for HmacSha3256 {
    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;
}

impl MacStdStaticFn for HmacSha3256 {

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

}

impl MacStdInstanceFn for HmacSha3256 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha3256::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
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
        return Sha3256::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3384 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3384::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl HmacStdFeature for HmacSha3384 {}

impl HmacStdConst for HmacSha3384 {
    const HASH_BLOCK_SIZE: usize = Sha3384::RATE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha3384::MESSAGE_DIGEST_LEN;
}

impl HmacStdStaticFn for HmacSha3384 {}

impl HmacStdInstanceFn for HmacSha3384 {}

impl MacStdFeature for HmacSha3384 {}

impl MacStdConst for HmacSha3384 {
    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;
}

impl MacStdStaticFn for HmacSha3384 {

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

}

impl MacStdInstanceFn for HmacSha3384 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha3384::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
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
        return Sha3384::digest_oneshot(&self.outer[..], mac);

    }

}

impl HmacSha3512 {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let mut v: Self = Self{
            hash_state: Sha3512::new(),
            inner: [0; Self::HASH_BLOCK_SIZE],
            outer: [0; Self::HASH_BLOCK_SIZE + Self::HASH_MESSAGE_DIGEST_LEN]
        };
        v.rekey(key)?.reset()?;
        return Ok(v);
    }

}

impl HmacStdFeature for HmacSha3512 {}

impl HmacStdConst for HmacSha3512 {
    const HASH_BLOCK_SIZE: usize = Sha3512::RATE;
    const HASH_MESSAGE_DIGEST_LEN: usize = Sha3512::MESSAGE_DIGEST_LEN;
}

impl HmacStdStaticFn for HmacSha3512 {}

impl HmacStdInstanceFn for HmacSha3512 {}

impl MacStdFeature for HmacSha3512 {}

impl MacStdConst for HmacSha3512 {
    const MAC_LEN: usize = Self::HASH_MESSAGE_DIGEST_LEN;
}

impl MacStdStaticFn for HmacSha3512 {

    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError> {
        return Self::new(key)?.update(msg)?.compute(mac);
    }

}

impl MacStdInstanceFn for HmacSha3512 {

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {

        if key.len() > Self::HASH_BLOCK_SIZE {
            Sha3512::digest_oneshot(key, &mut self.inner[..Self::HASH_MESSAGE_DIGEST_LEN])?;
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
        return Sha3512::digest_oneshot(&self.outer[..], mac);

    }

}