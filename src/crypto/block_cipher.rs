use crate::crypto::error::CryptoError;

pub trait BlockCipherStdFeature: BlockCipherStdConst + BlockCipherStdInstanceFn {}

pub trait BlockCipherStdConst {
    const KEY_LEN: usize;
    const BLOCK_SIZE: usize;
}

pub trait BlockCipherStdInstanceFn {
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Result<(), CryptoError>;
    fn encrypt_overwrite(&self, block: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt_overwrite(&self, block: &mut [u8]) -> Result<(), CryptoError>;
    fn encrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn decrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn encrypt_overwrite_unchecked(&self, block: &mut [u8]);
    fn decrypt_overwrite_unchecked(&self, block: &mut [u8]);
}

pub trait BlockCipher128StdFeature: BlockCipher128StdConst + BlockCipher128StdInstanceFn {}
pub trait BlockCipher128StdConst: BlockCipherStdConst {}
pub trait BlockCipher128StdInstanceFn: BlockCipherStdInstanceFn {}