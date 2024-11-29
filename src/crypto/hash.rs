use crate::crypto::error::CryptoError;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::sha2::Sha512224;
use crate::crypto::sha2::Sha512256;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;

pub trait HashStdFeature: HashStdConst + HashStdStaticFn + HashStdInstanceFn {}

pub trait HashStdConst {
    const MESSAGE_DIGEST_LEN: usize;
}

pub trait HashStdStaticFn {
    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait HashStdInstanceFn {
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait BlockHashConst {
    const BLOCK_SIZE: usize = SHA2_32_BLOCK_SIZE;
}

pub enum HashAlgorithm {
    Null,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512224,
    Sha512256,
    Sha3224,
    Sha3256,
    Sha3384,
    Sha3512,
}

pub enum Hash {
    Null(()),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512224(Sha512224),
    Sha512256(Sha512256),
    Sha3224(Sha3224),
    Sha3256(Sha3256),
    Sha3384(Sha3384),
    Sha3512(Sha3512),
}

impl Hash {

    pub fn new(algo: HashAlgorithm) -> Self {
        return match algo {
            HashAlgorithm::Null      => Self::Null(()),
            HashAlgorithm::Sha224    => Self::Sha224(Sha224::new()),
            HashAlgorithm::Sha256    => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384    => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512    => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha512224 => Self::Sha512224(Sha512224::new()),
            HashAlgorithm::Sha512256 => Self::Sha512256(Sha512256::new()),
            HashAlgorithm::Sha3224   => Self::Sha3224(Sha3224::new()),
            HashAlgorithm::Sha3256   => Self::Sha3256(Sha3256::new()),
            HashAlgorithm::Sha3384   => Self::Sha3384(Sha3384::new()),
            HashAlgorithm::Sha3512   => Self::Sha3512(Sha3512::new()),
        };
    }

    pub fn digest_oneshot(algo: HashAlgorithm, msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            HashAlgorithm::Null      => Ok(()),
            HashAlgorithm::Sha224    => Sha224::digest_oneshot(msg, md),
            HashAlgorithm::Sha256    => Sha256::digest_oneshot(msg, md),
            HashAlgorithm::Sha384    => Sha384::digest_oneshot(msg, md),
            HashAlgorithm::Sha512    => Sha512::digest_oneshot(msg, md),
            HashAlgorithm::Sha512224 => Sha512224::digest_oneshot(msg, md),
            HashAlgorithm::Sha512256 => Sha512256::digest_oneshot(msg, md),
            HashAlgorithm::Sha3224   => Sha3224::digest_oneshot(msg, md),
            HashAlgorithm::Sha3256   => Sha3256::digest_oneshot(msg, md),
            HashAlgorithm::Sha3384   => Sha3384::digest_oneshot(msg, md),
            HashAlgorithm::Sha3512   => Sha3512::digest_oneshot(msg, md),
        };
    }

}

impl HashInstanceFn for Hash {

    fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Null(())     => None,
            Self::Sha224(h)    => h.reset().err(),
            Self::Sha256(h)    => h.reset().err(),
            Self::Sha384(h)    => h.reset().err(),
            Self::Sha512(h)    => h.reset().err(),
            Self::Sha512224(h) => h.reset().err(),
            Self::Sha512256(h) => h.reset().err(),
            Self::Sha3224(h)   => h.reset().err(),
            Self::Sha3256(h)   => h.reset().err(),
            Self::Sha3384(h)   => h.reset().err(),
            Self::Sha3512(h)   => h.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Null(())     => None,
            Self::Sha224(h)    => h.update(msg).err(),
            Self::Sha256(h)    => h.update(msg).err(),
            Self::Sha384(h)    => h.update(msg).err(),
            Self::Sha512(h)    => h.update(msg).err(),
            Self::Sha512224(h) => h.update(msg).err(),
            Self::Sha512256(h) => h.update(msg).err(),
            Self::Sha3224(h)   => h.update(msg).err(),
            Self::Sha3256(h)   => h.update(msg).err(),
            Self::Sha3384(h)   => h.update(msg).err(),
            Self::Sha3512(h)   => h.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {
        return if let Some(e) = match self {
            Self::Null(())     => None,
            Self::Sha224(h)    => h.digest(md).err(),
            Self::Sha256(h)    => h.digest(md).err(),
            Self::Sha384(h)    => h.digest(md).err(),
            Self::Sha512(h)    => h.digest(md).err(),
            Self::Sha512224(h) => h.digest(md).err(),
            Self::Sha512256(h) => h.digest(md).err(),
            Self::Sha3224(h)   => h.digest(md).err(),
            Self::Sha3256(h)   => h.digest(md).err(),
            Self::Sha3384(h)   => h.digest(md).err(),
            Self::Sha3512(h)   => h.digest(md).err(),
        } { Err(e) } else { Ok(()) };
    }

}