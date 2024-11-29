use crate::crypto::error::CryptoError;

pub trait Aead {
    const KEY_LEN: usize;
    const MIN_NONCE_LEN: usize;
    const MAX_NONCE_LEN: usize;
    const TAG_LEN: usize;
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
    fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError>;
}

pub trait BlockCipher {
    const KEY_LEN: usize;
    const BLOCK_SIZE: usize;
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

pub trait BlockCipher128: BlockCipher {}

pub trait DiffieHellman {
    const PRIVATE_KEY_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SHARED_SECRET_LEN: usize;
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn compute_shared_secret_oneshot(priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignatureSigner {
    const PRIVATE_KEY_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    fn compute_public_key_oneshot(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign_oneshot(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
    fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError>;
    fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait DigitalSignatureVerifier {
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    fn verify_oneshot(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

pub trait Hash {
    const MESSAGE_DIGEST_LEN: usize;
    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait BlockHash: Hash {
    const BLOCK_SIZE: usize;
}

pub trait Hmac: Mac {
    const HASH_BLOCK_SIZE: usize;
    const HASH_MESSAGE_DIGEST_LEN: usize;
}

pub trait Mac {
    const MAC_LEN: usize;
    fn compute_oneshot(key: &[u8], msg: &[u8], mac: &mut [u8]) -> Result<(), CryptoError>;
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait StreamCipher {
    const KEY_LEN: usize;
    fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError>;
    fn encrypt_or_decrypt(&mut self, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
    fn encrypt_or_decrypt_overwrite(&mut self, text: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait Xof {
    fn output_oneshot(msg: &[u8], output: &mut [u8], d: usize) -> Result<(), CryptoError>;
    fn reset(&mut self) -> Result<&mut Self, CryptoError>;
    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError>;
    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError>;
}