

use crate::crypto::hmac_sha2::HmacSha224;
use crate::crypto::hmac_sha2::HmacSha256;
use crate::crypto::hmac_sha2::HmacSha384;
use crate::crypto::hmac_sha2::HmacSha512;
use crate::crypto::hmac_sha3::HmacSha3224;
use crate::crypto::hmac_sha3::HmacSha3256;
use crate::crypto::hmac_sha3::HmacSha3384;
use crate::crypto::hmac_sha3::HmacSha3512;

pub trait HmacStdFeature: HmacStdConst + HmacStdStaticFn + HmacStdInstanceFn {}

pub trait HmacStdConst: MacStdConst {
    const HASH_BLOCK_SIZE: usize;
    const HASH_MESSAGE_DIGEST_LEN: usize;
}

pub trait HmacStdStaticFn: MacStdStaticFn {}

pub trait HmacStdInstanceFn: MacStdInstanceFn {}
