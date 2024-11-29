use crate::crypto::block_cipher::BlockCipherStdFeature;
use crate::crypto::block_cipher::BlockCipher128StdFeature;
use crate::crypto::error::CryptoError;
use crate::crypto::error::CryptoErrorCode;

#[allow(private_bounds)]
pub trait Ecb128: Ecb {
    fn ecb_encrypt_blocks(cipher: &impl BlockCipher128StdFeature, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks(cipher: &impl BlockCipher128StdFeature, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_encrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature,
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature,
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cbc128: Cbc {
    fn cbc_encrypt_blocks(cipher: &impl BlockCipher128StdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks(cipher: &impl BlockCipher128StdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_encrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait CbcCts128: CbcCts {
    fn cbc_cts_encrypt(cipher: &impl BlockCipher128StdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt(cipher: &impl BlockCipher128StdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb1: CfbFb1 {
    fn cfb_fb1_encrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb8: CfbFb8 {
    fn cfb_fb8_encrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb128: CfbFb128 {
    fn cfb_fb128_encrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ofb128: Ofb {
    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
    fn ofb_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ctr128: Ctr {
    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipher128StdFeature, ctrblk: &mut [u8],
        ctrsize: usize, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
    fn ctr_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, ctrblk: &mut [u8],
        ctrsize: usize, text: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ccm128: Ccm {
    fn ccm_encrypt_and_generate(cipher: &impl BlockCipher128StdFeature, nonce: &[u8], ad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify(cipher: &impl BlockCipher128StdFeature, nonce: &[u8], ad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
    fn ccm_encrypt_and_generate_overwrite(cipher: &impl BlockCipher128StdFeature, nonce: &[u8],
        ad: &[u8], text: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify_overwrite(cipher: &impl BlockCipher128StdFeature, nonce: &[u8],
        ad: &[u8], text: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
}

#[allow(private_bounds)]
pub trait Gcm128: Gcm {
    fn gcm_encrypt_and_generate(cipher: &impl BlockCipher128StdFeature, iv: &[u8], aad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify(cipher: &impl BlockCipher128StdFeature, iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
    fn gcm_encrypt_and_generate_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        aad: &[u8], text: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        aad: &[u8], text: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
}

#[allow(private_bounds)]
pub trait Cmac128: Cmac {
    fn cmac_compute(cipher: &impl BlockCipher128StdFeature, msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}

pub struct BlockCipherMode128;

impl Ecb for BlockCipherMode128 {

    fn ecb_encrypt_blocks(cipher: &impl BlockCipherStdFeature, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if len != ciphertext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(&plaintext[i..j], &mut ciphertext[i..j]);
        }

        return Ok(());

    }

    fn ecb_decrypt_blocks(cipher: &impl BlockCipherStdFeature, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();

        if len != plaintext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            cipher.decrypt_unchecked(&ciphertext[i..j], &mut plaintext[i..j]);
        }

        return Ok(());

    }

    fn ecb_encrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature,
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            cipher.encrypt_overwrite_unchecked(&mut text[i..(i + 16)]);
        }

        return Ok(());

    }

    fn ecb_decrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature,
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            cipher.decrypt_overwrite_unchecked(&mut text[i..(i + 16)]);
        }

        return Ok(());

    }

}

impl Ecb128 for BlockCipherMode128 {

    fn ecb_encrypt_blocks(cipher: &impl BlockCipher128StdFeature, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_encrypt_blocks(cipher, plaintext, ciphertext);
    }

    fn ecb_decrypt_blocks(cipher: &impl BlockCipher128StdFeature, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_decrypt_blocks(cipher, ciphertext, plaintext);
    }

    fn ecb_encrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature,
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_encrypt_blocks_overwrite(cipher, text);
    }

    fn ecb_decrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature,
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_decrypt_blocks_overwrite(cipher, text);
    }

}

impl Cbc for BlockCipherMode128 {

    fn cbc_encrypt_blocks(cipher: &impl BlockCipherStdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if len != ciphertext.len() || iv.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut prev_ct: &[u8] = iv;
        let mut temp: [u8; 16] = [0; 16];

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            xor_block_128(&plaintext[i..j], prev_ct, &mut temp[..]);
            cipher.encrypt_unchecked(&temp[..], &mut ciphertext[i..j]);
            prev_ct = &ciphertext[i..j];
        }

        return Ok(());

    }

    fn cbc_decrypt_blocks(cipher: &impl BlockCipherStdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();

        if len != plaintext.len() || iv.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut prev_ct: &[u8] = iv;
        let mut temp: [u8; 16] = [0; 16];

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            cipher.decrypt_unchecked(&ciphertext[i..j], &mut temp[..]);
            xor_block_128(&temp[..], prev_ct, &mut plaintext[i..j]);
            prev_ct = &ciphertext[i..j];
        }

        return Ok(());

    }

    fn cbc_encrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if iv.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut prev_ct: &[u8] = iv;
        let mut temp: [u8; 16] = [0; 16];

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            xor_block_128(&text[i..j], prev_ct, &mut temp[..]);
            cipher.encrypt_unchecked(&temp[..], &mut text[i..j]);
            prev_ct = &text[i..j];
        }

        return Ok(());

    }

    fn cbc_decrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if iv.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut prev_ct: [u8; 16] = [0; 16];
        let mut temp: [u8; 16] = [0; 16];

        prev_ct.copy_from_slice(iv);

        for i in (0..len).step_by(16) {
            let j: usize = i + 16;
            temp.copy_from_slice(&text[i..j]);
            cipher.decrypt_overwrite_unchecked(&mut text[i..j]);
            xor_block_128_overwrite(&prev_ct[..], &mut text[i..j]);
            prev_ct.copy_from_slice(&temp[..]);
        }

        return Ok(());

    }

}

impl Cbc128 for BlockCipherMode128 {

    fn cbc_encrypt_blocks(cipher: &impl BlockCipher128StdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_encrypt_blocks(cipher, iv, plaintext, ciphertext);
    }

    fn cbc_decrypt_blocks(cipher: &impl BlockCipher128StdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_decrypt_blocks(cipher, iv, ciphertext, plaintext);
    }

    fn cbc_encrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_encrypt_blocks_overwrite(cipher, iv, text);
    }

    fn cbc_decrypt_blocks_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_decrypt_blocks_overwrite(cipher, iv, text);
    }

}

impl CfbFb8 for BlockCipherMode128 {

    fn cfb_fb8_encrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if len != ciphertext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in 0..len {
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            ciphertext[i] = plaintext[i] ^ b[0];
            for j in 1..16 {
                sftreg[j - 1] = sftreg[j];
            }
            sftreg[15] = ciphertext[i];
        }

        return Ok(());

    }

    fn cfb_fb8_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();

        if len != plaintext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in 0..len {
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            for j in 1..16 {
                sftreg[j - 1] = sftreg[j];
            }
            sftreg[15] = ciphertext[i];
            plaintext[i] = ciphertext[i] ^ b[0];
        }

        return Ok(());

    }

    fn cfb_fb8_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        if sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let len: usize = text.len();
        let mut b: [u8; 16] = [0; 16];

        for i in 0..len {
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            text[i] = text[i] ^ b[0];
            for j in 1..16 {
                sftreg[j - 1] = sftreg[j];
            }
            sftreg[15] = text[i];
        }

        return Ok(());

    }

    fn cfb_fb8_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        if sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let len: usize = text.len();
        let mut b: [u8; 16] = [0; 16];

        for i in 0..len {
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            for j in 1..16 {
                sftreg[j - 1] = sftreg[j];
            }
            sftreg[15] = text[i];
            text[i] = text[i] ^ b[0];
        }

        return Ok(());

    }

}

impl Cfb128Fb8 for BlockCipherMode128 {

    fn cfb_fb8_encrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_encrypt(cipher, sftreg, plaintext, ciphertext);
    }

    fn cfb_fb8_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_decrypt(cipher, sftreg, ciphertext, plaintext);
    }

    fn cfb_fb8_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_encrypt_overwrite(cipher, sftreg, text);
    }

    fn cfb_fb8_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_decrypt_overwrite(cipher, sftreg, text);
    }

}

impl CfbFb128 for BlockCipherMode128 {

    fn cfb_fb128_encrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if len != ciphertext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..(len & usize::MAX.wrapping_shl(4))).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            xor_block_128(&plaintext[i..j], &b[..], &mut ciphertext[i..j]);
            sftreg.copy_from_slice(&ciphertext[i..j]);
        }

        return Ok(());

    }

    fn cfb_fb128_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();

        if len != plaintext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..(len & usize::MAX.wrapping_shl(4))).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            sftreg.copy_from_slice(&ciphertext[i..j]);
            xor_block_128(&ciphertext[i..j], &b[..], &mut plaintext[i..j]);
        }

        return Ok(());

    }

    fn cfb_fb128_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..(len & usize::MAX.wrapping_shl(4))).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            xor_block_128_overwrite(&b[..], &mut text[i..j]);
            sftreg.copy_from_slice(&text[i..j]);
        }

        return Ok(());

    }

    fn cfb_fb128_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();

        if sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..(len & usize::MAX.wrapping_shl(4))).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            sftreg.copy_from_slice(&text[i..j]);
            xor_block_128_overwrite(&b[..], &mut text[i..j]);
        }

        return Ok(());

    }

}

impl Cfb128Fb128 for BlockCipherMode128 {

    fn cfb_fb128_encrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_encrypt(cipher, sftreg, plaintext, ciphertext);
    }

    fn cfb_fb128_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_decrypt(cipher, sftreg, ciphertext, plaintext);
    }

    fn cfb_fb128_encrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_encrypt_overwrite(cipher, sftreg, text);
    }

    fn cfb_fb128_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_decrypt_overwrite(cipher, sftreg, text);
    }

}

impl Ofb for BlockCipherMode128 {

    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len != outtext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_overwrite_unchecked(sftreg);
            xor_block_128(&intext[i..j], sftreg, &mut outtext[i..j]);
        }

        if n != len {
            cipher.encrypt_overwrite_unchecked(sftreg);
            for i in n..len {
                outtext[i] = intext[i] ^ sftreg[i - n];
            }
        }

        return Ok(());

    }

    fn ofb_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {

        if sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let len: usize = text.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_overwrite_unchecked(sftreg);
            xor_block_128_overwrite(sftreg, &mut text[i..j]);
        }

        if n != len {
            cipher.encrypt_overwrite_unchecked(sftreg);
            for i in n..len {
                text[i] = text[i] ^ sftreg[i - n];
            }
        }

        return Ok(());

    }

}

impl Ofb128 for BlockCipherMode128 {

    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ofb>::ofb_encrypt_or_decrypt(cipher, sftreg, intext, outtext);
    }

    fn ofb_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ofb>::ofb_encrypt_or_decrypt_overwrite(cipher, sftreg, text);
    }

}

impl Ctr for BlockCipherMode128 {

    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipherStdFeature, ctrblk: &mut [u8], ctrsize: usize,
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len != outtext.len() || ctrblk.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if ctrsize > 16 {
            return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
        } else if ctrsize < 8 {
            if ((n >> 4) + (if n != len { 1 } else { 0 })) > (1 << (ctrsize << 3)) {
                return Err(CryptoError::new(CryptoErrorCode::CounterOverwrapped));
            }
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor_block_128(&intext[i..j], &b[..], &mut outtext[i..j]);
            increment_counter_block_128(ctrblk, ctrsize);
        }

        if n != len {
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            for i in n..len {
                outtext[i] = intext[i] ^ b[i - n];
            }
            increment_counter_block_128(ctrblk, ctrsize);
        }

        return Ok(());

    }

    fn ctr_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, ctrblk: &mut [u8],
        ctrsize: usize, text: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = text.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if ctrblk.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if ctrsize > 16 {
            return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
        } else if ctrsize < 8 {
            if ((n >> 4) + (if n != len { 1 } else { 0 })) > (1 << (ctrsize << 3)) {
                return Err(CryptoError::new(CryptoErrorCode::CounterOverwrapped));
            }
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor_block_128_overwrite(&b[..], &mut text[i..j]);
            increment_counter_block_128(ctrblk, ctrsize);
        }

        if n != len {
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            for i in n..len {
                text[i] = text[i] ^ b[i - n];
            }
            increment_counter_block_128(ctrblk, ctrsize);
        }

        return Ok(());

    }

}

impl Ctr128 for BlockCipherMode128 {

    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipher128StdFeature, ctrblk: &mut [u8],
        ctrsize: usize, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, ctrblk, ctrsize, intext, outtext);
    }

    fn ctr_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipher128StdFeature, ctrblk: &mut [u8],
        ctrsize: usize, text: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ctr>::ctr_encrypt_or_decrypt_overwrite(cipher, ctrblk, ctrsize, text);
    }

}

impl Ccm for BlockCipherMode128 {

    fn ccm_encrypt_and_generate(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError> {

        let nlen: usize = nonce.len();
        let tlen: usize = cbc_mac.len();
        let q: usize = 15 - nlen;

        if nlen < 7 || nlen > 13 ||
            plaintext.len() != ciphertext.len() ||
            tlen & 1 == 1 || tlen < 4 || tlen > 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr: [u8; 16] = [0; 16];
        ctr[0] = ((14 - nlen) as u8) & 0x07;
        ctr[1..(1 + nlen)].copy_from_slice(nonce);

        let mut t: [u8; 16] = [0; 16];
        ccm128_compute_cbc_mac(cipher, nonce, ad, plaintext, &mut t, tlen);

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, &t[..tlen], cbc_mac)?;
        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, plaintext, ciphertext)?;

        return Ok(());

    }

    fn ccm_decrypt_and_verify(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError> {

        let nlen: usize = nonce.len();
        let tlen: usize = cbc_mac.len();
        let q: usize = 15 - nlen;

        if nlen < 7 || nlen > 13 ||
            ciphertext.len() != plaintext.len() ||
            tlen & 1 == 1 || tlen < 4 || tlen > 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr: [u8; 16] = [0; 16];
        ctr[0] = ((14 - nlen) as u8) & 0x07;
        ctr[1..(1 + nlen)].copy_from_slice(nonce);

        let mut t: [u8; 16] = [0; 16];
        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, cbc_mac, &mut t[..cbc_mac.len()])?;
        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, ciphertext, plaintext)?;

        let mut u: [u8; 16] = [0; 16];
        ccm128_compute_cbc_mac(cipher, nonce, ad, plaintext, &mut u, cbc_mac.len());

        let mut s: u8 = 0;
        for i in 0..cbc_mac.len() {
            s = s | (t[i] ^ u[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        return Ok(true);

    }

    fn ccm_encrypt_and_generate_overwrite(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        text: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError> {

        let nlen: usize = nonce.len();
        let tlen: usize = cbc_mac.len();
        let q: usize = 15 - nlen;

        if nlen < 7 || nlen > 13 || tlen & 1 == 1 || tlen < 4 || tlen > 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr: [u8; 16] = [0; 16];
        ctr[0] = ((14 - nlen) as u8) & 0x07;
        ctr[1..(1 + nlen)].copy_from_slice(nonce);

        let mut t: [u8; 16] = [0; 16];
        ccm128_compute_cbc_mac(cipher, nonce, ad, text, &mut t, tlen);

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, &t[..tlen], cbc_mac)?;
        <Self as Ctr>::ctr_encrypt_or_decrypt_overwrite(cipher, &mut ctr, q, text)?;

        return Ok(());

    }

    fn ccm_decrypt_and_verify_overwrite(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        text: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError> {

        let nlen: usize = nonce.len();
        let tlen: usize = cbc_mac.len();
        let q: usize = 15 - nlen;

        if nlen < 7 || nlen > 13 || tlen & 1 == 1 || tlen < 4 || tlen > 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let mut ctr: [u8; 16] = [0; 16];
        ctr[0] = ((14 - nlen) as u8) & 0x07;
        ctr[1..(1 + nlen)].copy_from_slice(nonce);

        let mut t: [u8; 16] = [0; 16];
        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr, q, cbc_mac, &mut t[..cbc_mac.len()])?;
        <Self as Ctr>::ctr_encrypt_or_decrypt_overwrite(cipher, &mut ctr, q, text)?;

        let mut u: [u8; 16] = [0; 16];
        ccm128_compute_cbc_mac(cipher, nonce, ad, text, &mut u, cbc_mac.len());

        let mut s: u8 = 0;
        for i in 0..cbc_mac.len() {
            s = s | (t[i] ^ u[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        return Ok(true);

    }

}

impl Ccm128 for BlockCipherMode128 {

    fn ccm_encrypt_and_generate(cipher: &impl BlockCipher128StdFeature, nonce: &[u8], ad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ccm>::ccm_encrypt_and_generate(cipher, nonce, ad, plaintext, ciphertext,
            cbc_mac);
    }

    fn ccm_decrypt_and_verify(cipher: &impl BlockCipher128StdFeature, nonce: &[u8], ad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError> {
        return <Self as Ccm>::ccm_decrypt_and_verify(cipher, nonce, ad, ciphertext, plaintext,
            cbc_mac);
    }

    fn ccm_encrypt_and_generate_overwrite(cipher: &impl BlockCipher128StdFeature, nonce: &[u8],
        ad: &[u8], text: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ccm>::ccm_encrypt_and_generate_overwrite(cipher, nonce, ad, text, cbc_mac);
    }

    fn ccm_decrypt_and_verify_overwrite(cipher: &impl BlockCipher128StdFeature, nonce: &[u8],
        ad: &[u8], text: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError> {
        return <Self as Ccm>::ccm_decrypt_and_verify_overwrite(cipher, nonce, ad, text, cbc_mac);
    }

}

impl Gcm for BlockCipherMode128 {

    fn gcm_encrypt_and_generate(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {

        if plaintext.len() != ciphertext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128 = gcm128_generate_subkey(cipher);

        let mut ctr0: [u8; 16] = [0; 16];
        gcm128_set_counter(&subkey, &iv, &mut ctr0[..]);

        let mut ctr: [u8; 16] = [0; 16];
        let mut a: usize = 1;
        for i in (0..16).rev() {
            a = a + (ctr0[i] as usize);
            ctr[i] = a as u8;
            a = a >> 8;
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr[..], 4, plaintext, ciphertext)?;
        gcm128_compute_tag(cipher, &subkey, &mut ctr0[..], aad, ciphertext, tag);

        return Ok(());

    }

    fn gcm_decrypt_and_verify(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {

        if ciphertext.len() != plaintext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128 = gcm128_generate_subkey(cipher);

        let mut ctr: [u8; 16] = [0; 16];
        gcm128_set_counter(&subkey, &iv, &mut ctr[..]);

        let mut t: [u8; 16] = [0; 16];
        gcm128_compute_tag(cipher, &subkey, &mut ctr[..], aad, ciphertext, &mut t[..]);

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ t[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr[..], 4, ciphertext, plaintext)?;
        return Ok(true);

    }

    fn gcm_encrypt_and_generate_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        text: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {

        if tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128 = gcm128_generate_subkey(cipher);

        let mut ctr0: [u8; 16] = [0; 16];
        gcm128_set_counter(&subkey, &iv, &mut ctr0[..]);

        let mut ctr: [u8; 16] = [0; 16];
        let mut a: usize = 1;
        for i in (0..16).rev() {
            a = a + (ctr0[i] as usize);
            ctr[i] = a as u8;
            a = a >> 8;
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt_overwrite(cipher, &mut ctr[..], 4, text)?;
        gcm128_compute_tag(cipher, &subkey, &mut ctr0[..], aad, text, tag);

        return Ok(());

    }

    fn gcm_decrypt_and_verify_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        text: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {

        if tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128 = gcm128_generate_subkey(cipher);

        let mut ctr: [u8; 16] = [0; 16];
        gcm128_set_counter(&subkey, &iv, &mut ctr[..]);

        let mut t: [u8; 16] = [0; 16];
        gcm128_compute_tag(cipher, &subkey, &mut ctr[..], aad, text, &mut t[..]);

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ t[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt_overwrite(cipher, &mut ctr[..], 4, text)?;
        return Ok(true);

    }

}

impl Gcm128 for BlockCipherMode128 {

    fn gcm_encrypt_and_generate(cipher: &impl BlockCipher128StdFeature, iv: &[u8], aad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Gcm>::gcm_encrypt_and_generate(cipher, iv, aad, plaintext, ciphertext, tag);
    }

    fn gcm_decrypt_and_verify(cipher: &impl BlockCipher128StdFeature, iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {
        return <Self as Gcm>::gcm_decrypt_and_verify(cipher, iv, aad, ciphertext, plaintext, tag);
    }

    fn gcm_encrypt_and_generate_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        aad: &[u8], text: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Gcm>::gcm_encrypt_and_generate_overwrite(cipher, iv, aad, text, tag);
    }

    fn gcm_decrypt_and_verify_overwrite(cipher: &impl BlockCipher128StdFeature, iv: &[u8],
        aad: &[u8], text: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {
        return <Self as Gcm>::gcm_decrypt_and_verify_overwrite(cipher, iv, aad, text, tag);
    }

}

static GCM_R: Block128 = Block128{
    l64: 0xe100000000000000,
    r64: 0x0000000000000000
};

fn xor_block_128(lhs: &[u8], rhs: &[u8], res: &mut [u8]) {
    for i in 0..16 {
        res[i] = lhs[i] ^ rhs[i];
    }
}

fn xor_block_128_overwrite(rhs: &[u8], res: &mut [u8]) {
    for i in 0..16 {
        res[i] = res[i] ^ rhs[i];
    }
}

fn increment_counter_block_128(ctrblk: &mut [u8], ctrsize: usize) {
    let mut a: usize = 1;
    for i in ((ctrsize & 15)..16).rev() {
        a = a + (ctrblk[i] as usize);
        ctrblk[i] = a as u8;
        a = a >> 8;
    }
}

fn ccm128_compute_cbc_mac(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8], plaintext: &[u8],
    cbc_mac_buf: &mut [u8; 16], cbc_mac_len: usize) {

    let mut s: [u8; 16] = [0; 16];
    let mut r: usize;
    let nlen: usize = nonce.len();
    let alen: usize = ad.len();
    let plen: usize = plaintext.len();
    let elen: usize =
        if alen > 0                 { 2 } else { 0 } +
        if alen > (65536 - 256) - 1 { 4 } else { 0 } +
        if alen > u32::MAX as usize { 4 } else { 0 };

    s[0] =
        if alen != 0 { 0x40 } else { 0x00 }       ^
        ((((cbc_mac_len - 2) as u8) << 2) & 0x38) ^
        ((14 - nlen) as u8);
    for i in 0..nlen {
        s[i + 1] = nonce[i];
    }
    r = (15 - nlen) << 3;
    for i in (nlen + 1)..16 {
        r = r - 8;
        s[i] = (plen >> r) as u8;
    }

    cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);

    if alen != 0 {

        let t: usize = match elen {
            6  => {
                s[0] = 0xff;
                s[1] = 0xfe;
                2
            },
            10 => {
                s[0] = 0xff;
                s[1] = 0xff;
                2
            }
            _  => 0
        };
        r = (elen - t) << 3;
        for i in t..elen {
            r = r - 8;
            s[i] = (alen >> r) as u8;
        }
        let t: usize = if alen < 16 - elen { alen } else { 16 - elen };
        for i in 0..t {
            s[i + elen] = ad[i];
        }
        for i in (t + elen)..16 {
            s[i] = 0x00;
        }

        xor_block_128_overwrite(&cbc_mac_buf[..], &mut s[..]);
        cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);

        let n: usize = {
            let mut i: usize = t;
            let n: usize = (alen - i) & (usize::MAX << 4);
            loop {
                if !(i < n) {
                    break i;
                }
                xor_block_128(&ad[i..(i + 16)], &cbc_mac_buf[..], &mut s[..]);
                cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);
                i = i + 16;
            }
        };

        if n != alen {
            for i in 0..(alen - n) {
                s[i] = cbc_mac_buf[i] ^ ad[i + n];
            }
            for i in (alen - n)..16 {
                s[i] = cbc_mac_buf[i];
            }
            cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);
        }

    }

    let n: usize = plen & (usize::MAX << 4);

    for i in (0..n).step_by(16) {
        xor_block_128(&plaintext[i..(i + 16)], &cbc_mac_buf[..], &mut s[..]);
        cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);
    }

    if n != plen {
        for i in 0..(plen - n) {
            s[i] = cbc_mac_buf[i] ^ plaintext[i + n];
        }
        for i in (plen - n)..16 {
            s[i] = cbc_mac_buf[i];
        }
        cipher.encrypt_unchecked(&s[..], &mut cbc_mac_buf[..]);
    }

}

fn gcm128_compute_tag(cipher: &impl BlockCipherStdFeature, subkey: &Block128, ctrblk: &mut [u8],
    aad: &[u8], intext: &[u8], tag: &mut [u8]) {
    let mut state: Block128 = Block128::from_u64_pair(0, 0);
    gcm128_ghash(subkey, &mut state, aad);
    gcm128_ghash(subkey, &mut state, intext);
    gcm128_ghash_block(
        subkey,
        &mut state,
        &Block128::from_u64_pair((aad.len() as u64) << 3, (intext.len() as u64) << 3)
    );
    <BlockCipherMode128 as Ctr>::ctr_encrypt_or_decrypt(
        cipher,
        ctrblk,
        0,
        &state.to_bytes()[..],
        tag
    ).unwrap();
}

fn gcm128_ghash(subkey: &Block128, state: &mut Block128, intext: &[u8]) {

    let len: usize = intext.len();
    let n: usize = len & usize::MAX.wrapping_shl(4);

    for i in (0..n).step_by(16) {
        let j: usize = i + 16;
        gcm128_ghash_block(subkey, state, &Block128::from_bytes(&intext[i..j]));
    }

    if n != len {
        gcm128_ghash_block(subkey, state, &{
            let mut l: u64   = 0;
            let mut r: u64   = 0;
            let mut i: usize = n;
            let mut j: usize = 64;
            while i < len && j >= 8 {
                j = j - 8;
                l = l | ((intext[i] as u64) << j);
                i = i + 1;
            }
            j = 64;
            while i < len {
                j = j - 8;
                r = r | ((intext[i] as u64) << j);
                i = i + 1;
            }
            Block128::from_u64_pair(l, r)
        });
    }

}

fn gcm128_ghash_block(subkey: &Block128, state: &mut Block128, block_in: &Block128) {

    let mut v: Block128 = subkey.clone();
    let b: Block128 = Block128::from_u64_pair(
        block_in.l64 ^ state.l64,
        block_in.r64 ^ state.r64
    );
    state.l64 = 0;
    state.r64 = 0;

    for i in (0..64).rev() {
        let mask: u64 = 0u64.wrapping_sub((b.l64 >> i) & 1);
        state.l64 = state.l64 ^ (v.l64 & mask);
        state.r64 = state.r64 ^ (v.r64 & mask);
        let mask: u64 = 0u64.wrapping_sub(v.r64 & 1);
        v.r64 = ((v.r64 >> 1) | ((v.l64 & 1) << 63)) ^ (GCM_R.r64 & mask);
        v.l64 =  (v.l64 >> 1)                        ^ (GCM_R.l64 & mask);
    }

    for i in (0..64).rev() {
        let mask: u64 = 0u64.wrapping_sub((b.r64 >> i) & 1);
        state.l64 = state.l64 ^ (v.l64 & mask);
        state.r64 = state.r64 ^ (v.r64 & mask);
        let mask: u64 = 0u64.wrapping_sub(v.r64 & 1);
        v.r64 = ((v.r64 >> 1) | ((v.l64 & 1) << 63)) ^ (GCM_R.r64 & mask);
        v.l64 =  (v.l64 >> 1)                        ^ (GCM_R.l64 & mask);
    }

}

fn gcm128_generate_subkey(cipher: &impl BlockCipher) -> Block128 {
    let mut h: [u8; 16] = [0; 16];
    cipher.encrypt_overwrite_unchecked(&mut h[..]);
    return Block128::from_bytes(&h[..]);
}

fn gcm128_set_counter(subkey: &Block128, iv: &[u8], ctrblk: &mut [u8]) {
    if iv.len() == 12 {
        ctrblk[..12].copy_from_slice(&iv[..]);
        ctrblk[12] = 0x00;
        ctrblk[13] = 0x00;
        ctrblk[14] = 0x00;
        ctrblk[15] = 0x01;
    } else {
        let mut s: Block128 = Block128::from_u64_pair(0, 0);
        gcm128_ghash(subkey, &mut s, iv);
        gcm128_ghash_block(subkey, &mut s, &Block128::from_u64_pair(0, (iv.len() as u64) << 3));
        s.into_bytes(ctrblk);
    }
}

struct Block128 {
    l64: u64,
    r64: u64
}

impl Block128 {

    fn from_u64_pair(l64: u64, r64: u64) -> Self {
        return Self{
            l64: l64,
            r64: r64
        };
    }

    fn from_bytes(b: &[u8]) -> Self {
        return Self{
            l64: {
                ((b[ 0] as u64) << 56) |
                ((b[ 1] as u64) << 48) |
                ((b[ 2] as u64) << 40) |
                ((b[ 3] as u64) << 32) |
                ((b[ 4] as u64) << 24) |
                ((b[ 5] as u64) << 16) |
                ((b[ 6] as u64) <<  8) |
                  b[ 7] as u64
            },
            r64: {
                ((b[ 8] as u64) << 56) |
                ((b[ 9] as u64) << 48) |
                ((b[10] as u64) << 40) |
                ((b[11] as u64) << 32) |
                ((b[12] as u64) << 24) |
                ((b[13] as u64) << 16) |
                ((b[14] as u64) <<  8) |
                  b[15] as u64
            }
        };
    }

    fn into_bytes(&self, b: &mut [u8]) {
        b[ 0] = (self.l64 >> 56) as u8;
        b[ 1] = (self.l64 >> 48) as u8;
        b[ 2] = (self.l64 >> 40) as u8;
        b[ 3] = (self.l64 >> 32) as u8;
        b[ 4] = (self.l64 >> 24) as u8;
        b[ 5] = (self.l64 >> 16) as u8;
        b[ 6] = (self.l64 >>  8) as u8;
        b[ 7] =  self.l64        as u8;
        b[ 8] = (self.r64 >> 56) as u8;
        b[ 9] = (self.r64 >> 48) as u8;
        b[10] = (self.r64 >> 40) as u8;
        b[11] = (self.r64 >> 32) as u8;
        b[12] = (self.r64 >> 24) as u8;
        b[13] = (self.r64 >> 16) as u8;
        b[14] = (self.r64 >>  8) as u8;
        b[15] =  self.r64        as u8;
    }

    fn to_bytes(&self) -> [u8; 16] {
        return [
            (self.l64 >> 56) as u8,
            (self.l64 >> 48) as u8,
            (self.l64 >> 40) as u8,
            (self.l64 >> 32) as u8,
            (self.l64 >> 24) as u8,
            (self.l64 >> 16) as u8,
            (self.l64 >>  8) as u8,
             self.l64        as u8,
            (self.r64 >> 56) as u8,
            (self.r64 >> 48) as u8,
            (self.r64 >> 40) as u8,
            (self.r64 >> 32) as u8,
            (self.r64 >> 24) as u8,
            (self.r64 >> 16) as u8,
            (self.r64 >>  8) as u8,
             self.r64        as u8
        ];
    }

    fn clone(&self) -> Self {
        return Self{
            l64: self.l64,
            r64: self.r64
        };
    }

}

trait Ecb {
    fn ecb_encrypt_blocks(cipher: &impl BlockCipherStdFeature, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks(cipher: &impl BlockCipherStdFeature, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_encrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature,
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature,
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait Cbc {
    fn cbc_encrypt_blocks(cipher: &impl BlockCipherStdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks(cipher: &impl BlockCipherStdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_encrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait CbcCts {
    fn cbc_cts_encrypt(cipher: &impl BlockCipherStdFeature, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt(cipher: &impl BlockCipherStdFeature, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb1 {
    fn cfb_fb1_encrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb8 {
    fn cfb_fb8_encrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb128 {
    fn cfb_fb128_encrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_encrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ofb {
    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8], intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError>;
    fn ofb_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, sftreg: &mut [u8],
        text: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ctr {
    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipherStdFeature, ctrblk: &mut [u8], ctrsize: usize,
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
    fn ctr_encrypt_or_decrypt_overwrite(cipher: &impl BlockCipherStdFeature, ctrblk: &mut [u8],
        ctrsize: usize, text: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ccm {
    fn ccm_encrypt_and_generate(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
    fn ccm_encrypt_and_generate_overwrite(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        text: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify_overwrite(cipher: &impl BlockCipherStdFeature, nonce: &[u8], ad: &[u8],
        text: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
}

trait Gcm {
    fn gcm_encrypt_and_generate(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
    fn gcm_encrypt_and_generate_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        text: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify_overwrite(cipher: &impl BlockCipherStdFeature, iv: &[u8], aad: &[u8],
        text: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
}

trait Cmac {
    fn cmac_compute(cipher: &impl BlockCipherStdFeature, msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}