use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ccm128;
use crate::crypto::block_cipher_mode::Gcm128;
use crate::crypto::error::CryptoError;
use crate::crypto::feature::Aead;
use crate::crypto::feature::BlockCipher;

pub struct Aes128Ccm {
    aes: Aes128
}

pub struct Aes192Ccm {
    aes: Aes192
}

pub struct Aes256Ccm {
    aes: Aes256
}

impl Aes128Ccm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes128::new(key)? });
    }

}

impl Aes192Ccm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes192::new(key)? });
    }

}

impl Aes256Ccm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes256::new(key)? });
    }

}

impl Aead for Aes128Ccm {

    const KEY_LEN: usize       = Aes128::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes128::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}

impl Aead for Aes192Ccm {

    const KEY_LEN: usize       = Aes192::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes192::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}

impl Aead for Aes256Ccm {

    const KEY_LEN: usize       = Aes256::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes256::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::ccm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::ccm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}

pub struct Aes128Gcm {
    aes: Aes128
}

pub struct Aes192Gcm {
    aes: Aes192
}

pub struct Aes256Gcm {
    aes: Aes256
}

impl Aes128Gcm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes128::new(key)? });
    }

}

impl Aes192Gcm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes192::new(key)? });
    }

}

impl Aes256Gcm {

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        return Ok(Self{ aes: Aes256::new(key)? });
    }

}

impl Aead for Aes128Gcm {

    const KEY_LEN: usize       = Aes128::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes128::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}

impl Aead for Aes192Gcm {

    const KEY_LEN: usize       = Aes192::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes192::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}

impl Aead for Aes256Gcm {

    const KEY_LEN: usize       = Aes256::KEY_LEN;
    const MIN_NONCE_LEN: usize = 12; // from RFC 5116
    const MAX_NONCE_LEN: usize = 12; // from RFC 5116
    const TAG_LEN: usize       = Aes256::BLOCK_SIZE;

    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        self.aes.rekey(key)?;
        return Ok(self);
    }

    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate(&self.aes, nonce, aad, plaintext,
            ciphertext, tag);
    }

    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify(&self.aes, nonce, aad, ciphertext,
            plaintext, tag);
    }

    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return BlockCipherMode128::gcm_encrypt_and_generate_overwrite(&self.aes, nonce, aad, text, tag);
    }

    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return BlockCipherMode128::gcm_decrypt_and_verify_overwrite(&self.aes, nonce, aad, text, tag);
    }

}