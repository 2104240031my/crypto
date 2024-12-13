use crate::crypto::aes::Aes256;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::feature::BlockCipher;
use crate::crypto::feature::Hash;
use crate::crypto::feature::Mac;
use crate::crypto::feature::Xof;
use crate::crypto::feature::StreamCipher;
use crate::crypto::hmac_sha3::HmacSha3256;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Shake256;
use core::arch::x86_64::_rdseed64_step;
use core::arch::x86_64::_rdrand64_step;
use core::arch::x86_64::_rdtsc;

pub struct RandAes256 {
    aes256: Aes256,
    counter: usize
}

pub struct RandChaCha20 {
    chacha20: ChaCha20,
    counter: usize
}

const RDRAND64_MAX_TRYING_NUM: usize = 10;
const COUNTER_LIMIT: usize           = u32::MAX as usize;

impl RandAes256 {

    pub fn new() -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            aes256: Aes256::new(&[0; Aes256::KEY_LEN])?,
            counter: 0,
        };

        v.reseed()?;
        return Ok(v);

    }

    pub fn reseed(&mut self) -> Result<&mut Self, CryptoError> {

        let mut seed: [u8; 32] = [0; 32];

        for i in (0..32).step_by(8) {
            seed[i..(i + 8)].copy_from_slice(&rand64().to_ne_bytes());
        }

        let mut secret: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
        HmacSha3256::compute_oneshot(
            "salt for AES-256-CTR pseudo-random number generator".as_bytes(),
            &seed[..],
            &mut secret[..]
        )?;

        let mut buf: [u8; Sha3256::MESSAGE_DIGEST_LEN] = [0; Sha3256::MESSAGE_DIGEST_LEN];
        Sha3256::digest_oneshot(&secret[..], &mut buf[..])?;

        self.aes256.rekey(&mut buf[..Aes256::KEY_LEN])?;
        self.counter = 0;

        return Ok(self);

    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = buf.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);
        let mut i: usize = 0;

        if self.counter + ((n >> 4) + if len & 15 == 0 { 0 } else { 1 }) >= COUNTER_LIMIT {
            return Err(CryptoError::new(CryptoErrorCode::ReseedRequired));
        }

        while i < n {
            if self.counter >= COUNTER_LIMIT {
                self.reseed()?;
            }
            let counter: [u8; Aes256::BLOCK_SIZE] = (self.counter as u128).to_be_bytes();
            self.aes256.encrypt_unchecked(&counter[..], &mut buf[i..(i + Aes256::BLOCK_SIZE)]);
            self.counter = self.counter + 1;
            i = i + Aes256::BLOCK_SIZE;
        }

        if n != len {
            if self.counter >= COUNTER_LIMIT {
                self.reseed()?;
            }
            let mut counter: [u8; Aes256::BLOCK_SIZE] = (self.counter as u128).to_be_bytes();
            self.aes256.encrypt_overwrite_unchecked(&mut counter[..]);
            buf[i..].copy_from_slice(&counter[..(len - n)]);
            self.counter = self.counter + 1;
        }

        return Ok(());

    }

    pub fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = buf.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);
        let mut i: usize = 0;

        if self.counter + ((n >> 4) + if len & 15 == 0 { 0 } else { 1 }) >= COUNTER_LIMIT {
            return Err(CryptoError::new(CryptoErrorCode::ReseedRequired));
        }

        while i < n {
            let counter: [u8; Aes256::BLOCK_SIZE] = (self.counter as u128).to_be_bytes();
            self.aes256.encrypt_unchecked(&counter[..], &mut buf[i..(i + Aes256::BLOCK_SIZE)]);
            self.counter = self.counter + 1;
            i = i + Aes256::BLOCK_SIZE;
        }

        if n != len {
            let mut counter: [u8; Aes256::BLOCK_SIZE] = (self.counter as u128).to_be_bytes();
            self.aes256.encrypt_overwrite_unchecked(&mut counter[..]);
            buf[i..].copy_from_slice(&counter[..(len - n)]);
            self.counter = self.counter + 1;
        }

        return Ok(());

    }

}

impl RandChaCha20 {

    pub fn new() -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            chacha20: ChaCha20::new(&[0; ChaCha20::KEY_LEN], &[0; ChaCha20::NONCE_LEN], 0)?,
            counter: 0,
        };

        v.reseed()?;
        return Ok(v);

    }

    pub fn reseed(&mut self) -> Result<&mut Self, CryptoError> {

        let mut seed: [u8; 32] = [0; 32];

        for i in (0..32).step_by(8) {
            seed[i..(i + 8)].copy_from_slice(&rand64().to_ne_bytes());
        }

        let mut secret: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
        HmacSha3256::compute_oneshot(
            "salt for ChaCha20 pseudo-random number generator".as_bytes(),
            &seed[..],
            &mut secret[..]
        )?;

        let mut buf: [u8; ChaCha20::KEY_LEN + ChaCha20::NONCE_LEN] = [0; ChaCha20::KEY_LEN + ChaCha20::NONCE_LEN];
        Shake256::output_oneshot(&secret[..], &mut buf[..], ChaCha20::KEY_LEN + ChaCha20::NONCE_LEN)?;

        self.chacha20.rekey(&mut buf[..ChaCha20::KEY_LEN])?;
        self.chacha20.reset(&mut buf[ChaCha20::KEY_LEN..], 0)?;
        self.counter = 0;

        return Ok(self);

    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = buf.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);
        let mut i: usize = 0;

        while i < n {
            if self.counter >= COUNTER_LIMIT {
                self.reseed()?;
            }
            self.chacha20.set_counter(self.counter as u32)?;
            self.chacha20.block(&mut buf[i..(i + ChaCha20::BLOCK_SIZE)])?;
            self.counter = self.counter + 1;
            i = i + ChaCha20::BLOCK_SIZE;
        }

        if n != len {
            if self.counter >= COUNTER_LIMIT {
                self.reseed()?;
            }
            self.chacha20.set_counter(self.counter as u32)?;
            let mut k: [u8; ChaCha20::BLOCK_SIZE] = [0; ChaCha20::BLOCK_SIZE];
            self.chacha20.block(&mut k[..])?;
            buf[i..].copy_from_slice(&k[..(len - n)]);
            self.counter = self.counter + 1;
        }

        return Ok(());

    }

    pub fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = buf.len();
        let n: usize = len & usize::MAX.wrapping_shl(6);
        let mut i: usize = 0;

        if self.counter + ((n >> 6) + if len & 63 == 0 { 0 } else { 1 }) >= COUNTER_LIMIT {
            return Err(CryptoError::new(CryptoErrorCode::ReseedRequired));
        }

        while i < n {
            self.chacha20.set_counter(self.counter as u32)?;
            self.chacha20.block(&mut buf[i..(i + ChaCha20::BLOCK_SIZE)])?;
            self.counter = self.counter + 1;
            i = i + ChaCha20::BLOCK_SIZE;
        }

        if n != len {
            self.chacha20.set_counter(self.counter as u32)?;
            let mut k: [u8; ChaCha20::BLOCK_SIZE] = [0; ChaCha20::BLOCK_SIZE];
            self.chacha20.block(&mut k[..])?;
            buf[i..].copy_from_slice(&k[..(len - n)]);
            self.counter = self.counter + 1;
        }

        return Ok(());

    }

}

fn rand64() -> u64 {

    let mut rand: u64 = 0;

    if unsafe { _rdseed64_step(&mut rand) } == 1 {
        return rand;
    }

    for _ in 0..RDRAND64_MAX_TRYING_NUM {
        let mut rand: u64 = 0;
        if unsafe { _rdrand64_step(&mut rand) } == 1 {
            return rand;
        }
    }

    return unsafe { _rdtsc() };

}