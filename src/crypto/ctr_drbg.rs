use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::BlockCipher;
use crate::crypto::aes::Aes;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Gcm128;


pub struct Ctr128Drbg {
    v: [u8; 15],
    reseed_counter: u64
}

impl Ctr128Drbg {

    pub fn init(&mut self, cipher: &(impl BlockCipher + BlockCipher128), entropy_in: &[u8],
        personalization_in: &[u8]) -> Result<(), CryptoError> {

        let mut seed_material: [u8; 64];

        seed_material[..personalization_in.len()].copy_from_slice(personalization_in);
        for i in 0..64 {
            seed_material[i] = seed_material[i] ^ entropy_in[i];
        }



    }

    pub fn reseed(&mut self, cipher: &(impl BlockCipher + BlockCipher128), entropy_in: &[u8],
        additional_in: &[u8]) -> Result<(), CryptoError> {

        let mut seed_material: [u8; 64];

        seed_material[..additional_in.len()].copy_from_slice(additional_in);
        for i in 0..64 {
            seed_material[i] = seed_material[i] ^ entropy_in[i];
        }

        self.reseed_ctr = 1;
        return Ok(());

    }

    pub fn random_bytes(&mut self,  buf_out: &[u8]) -> Result<(), CryptoError> {


    }

}
