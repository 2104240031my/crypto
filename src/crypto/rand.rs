use crate::crypto::chacha20::ChaCha20;
use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;
use crate::crypto::feature::Mac;
use crate::crypto::feature::StreamCipher;
use crate::crypto::hmac_sha3::HmacSha3256;
use rdrand::RdRand;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub struct RandChaCha20 {
    chacha20: ChaCha20,
    counter: usize
}

const COUNTER_LIMIT: usize = u32::MAX as usize;
const CONTEXT_STRING: &str = "RandChaCha20 context string";

impl RandChaCha20 {

    pub fn new() -> Result<Self, CryptoError> {

        let mut v: Self = Self{
            chacha20: ChaCha20::new(
                &[0; ChaCha20::KEY_LEN],
                &[0; ChaCha20::NONCE_LEN],
                0
            )?,
            counter: 0,
        };

        v.reseed()?;
        return Ok(v);

    }

    pub fn reseed(&mut self) -> Result<&mut Self, CryptoError> {

        let mut rdrand: RdRand = RdRand::new()
            .map_err(|_| CryptoError::new(CryptoErrorCode::RandomGenerationFailed))?;

        let mut rand_bytes: [u8; 64] = [0; 64];

        let time1: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::new(CryptoErrorCode::RandomGenerationFailed))?
            .as_millis();
        rand_bytes[..16].copy_from_slice(&time1.to_be_bytes());

        rdrand.try_fill_bytes(&mut rand_bytes[16..48])
            .map_err(|_| CryptoError::new(CryptoErrorCode::RandomGenerationFailed))?;

        let time2: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::new(CryptoErrorCode::RandomGenerationFailed))?
            .as_millis();
        rand_bytes[48..].copy_from_slice(&time2.to_be_bytes());

        let mut secret: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];
        HmacSha3256::compute_oneshot(CONTEXT_STRING.as_bytes(), &rand_bytes[..], &mut secret[..])?;

        let mut buf: [u8; HmacSha3256::MAC_LEN] = [0; HmacSha3256::MAC_LEN];

        HmacSha3256::compute_oneshot(&secret[..], "chacha20 key".as_bytes(), &mut buf[..])?;
        self.chacha20.rekey(&mut buf[..ChaCha20::KEY_LEN])?;

        HmacSha3256::compute_oneshot(&secret[..], "chacha20 nonce".as_bytes(), &mut buf[..])?;
        self.chacha20.reset(&mut buf[..ChaCha20::NONCE_LEN], 0)?;

        return Ok(self);

    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {

        let mut i: usize = 0;
        let n: usize = buf.len();

        while i < n {

            if self.counter > COUNTER_LIMIT {
                return Err(CryptoError::new(CryptoErrorCode::ReseedRequired));
            }

            self.chacha20.set_counter(self.counter as u32)?;

            let t: usize = n - i;
            i = i + if t >= ChaCha20::BLOCK_SIZE {
                self.chacha20.block(&mut buf[i..(i + ChaCha20::BLOCK_SIZE)])?;
                ChaCha20::BLOCK_SIZE
            } else {
                let mut k: [u8; ChaCha20::BLOCK_SIZE] = [0; ChaCha20::BLOCK_SIZE];
                self.chacha20.block(&mut k[..])?;
                buf[i..].copy_from_slice(&k[..t]);
                t
            };

            self.counter = self.counter + 1;

        }

        return Ok(());

    }

}