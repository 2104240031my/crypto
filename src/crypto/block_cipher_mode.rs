use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::BlockCipher;
use crate::crypto::BlockCipher128;

#[allow(private_bounds)]
pub trait Ecb128: Ecb {
    fn ecb_encrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cbc128: Cbc {
    fn cbc_encrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait CbcCts128: CbcCts {
    fn cbc_cts_encrypt(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb1: CfbFb1 {
    fn cfb_fb1_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb8: CfbFb8 {
    fn cfb_fb8_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb128: CfbFb128 {
    fn cfb_fb128_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ofb128: Ofb {
    fn ofb_encrypt_or_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ctr128: Ctr {
    fn ctr_encrypt_or_decrypt(cipher: &(impl BlockCipher + BlockCipher128), ctrblk: &mut [u8],
        ctrsize: usize, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Ccm128: Ccm {
    fn ccm_encrypt_and_generate(cipher: &(impl BlockCipher + BlockCipher128), nonce: &[u8],
        ad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify(cipher: &(impl BlockCipher + BlockCipher128), nonce: &[u8],
        ad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
}

#[allow(private_bounds)]
pub trait Gcm128: Gcm {
    fn gcm_encrypt_and_generate(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
}

#[allow(private_bounds)]
pub trait Cmac128: Cmac {
    fn cmac_compute(cipher: &(impl BlockCipher + BlockCipher128), msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}

pub struct BlockCipherMode128 {}

impl Ecb for BlockCipherMode128 {

    fn ecb_encrypt_blocks(cipher: &impl BlockCipher, plaintext: &[u8],
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

    fn ecb_decrypt_blocks(cipher: &impl BlockCipher, ciphertext: &[u8],
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

}

impl Ecb128 for BlockCipherMode128 {

    fn ecb_encrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_encrypt_blocks(cipher, plaintext, ciphertext);
    }

    fn ecb_decrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ecb>::ecb_decrypt_blocks(cipher, ciphertext, plaintext);
    }

}

impl Cbc for BlockCipherMode128 {

    fn cbc_encrypt_blocks(cipher: &impl BlockCipher, iv: &[u8], plaintext: &[u8],
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
            xor(&plaintext[i..j], prev_ct, &mut temp[..], 16);
            cipher.encrypt_unchecked(&temp[..], &mut ciphertext[i..j]);
            prev_ct = &ciphertext[i..j];
        }

        return Ok(());

    }

    fn cbc_decrypt_blocks(cipher: &impl BlockCipher, iv: &[u8], ciphertext: &[u8],
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
            xor(&temp[..], prev_ct, &mut plaintext[i..j], 16);
            prev_ct = &ciphertext[i..j];
        }

        return Ok(());

    }

}

impl Cbc128 for BlockCipherMode128 {

    fn cbc_encrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_encrypt_blocks(cipher, iv, plaintext, ciphertext);
    }

    fn cbc_decrypt_blocks(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Cbc>::cbc_decrypt_blocks(cipher, iv, ciphertext, plaintext);
    }

}

impl CfbFb8 for BlockCipherMode128 {

    fn cfb_fb8_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
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

    fn cfb_fb8_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
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

}

impl Cfb128Fb8 for BlockCipherMode128 {

    fn cfb_fb8_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_encrypt(cipher, sftreg, plaintext, ciphertext);
    }

    fn cfb_fb8_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb8>::cfb_fb8_decrypt(cipher, sftreg, ciphertext, plaintext);
    }

}

impl CfbFb128 for BlockCipherMode128 {

    fn cfb_fb128_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len != ciphertext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            xor(&plaintext[i..j], &b[..], &mut ciphertext[i..j], 16);
            sftreg.copy_from_slice(&ciphertext[i..j]);
        }

        return Ok(());

    }

    fn cfb_fb128_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len != plaintext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        let mut b: [u8; 16] = [0; 16];

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(sftreg, &mut b[..]);
            sftreg.copy_from_slice(&ciphertext[i..j]);
            xor(&ciphertext[i..j], &b[..], &mut plaintext[i..j], 16);
        }

        return Ok(());

    }

}

impl Cfb128Fb128 for BlockCipherMode128 {

    fn cfb_fb128_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_encrypt(cipher, sftreg, plaintext, ciphertext);
    }

    fn cfb_fb128_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as CfbFb128>::cfb_fb128_decrypt(cipher, sftreg, ciphertext, plaintext);
    }

}

impl Ofb for BlockCipherMode128 {

    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len != outtext.len() || sftreg.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_and_overwrite_unchecked(sftreg);
            xor(&intext[i..j], sftreg, &mut outtext[i..j], 16);
        }

        if n != len {
            cipher.encrypt_and_overwrite_unchecked(sftreg);
            xor(&intext[n..len], sftreg, &mut outtext[n..len], len - n);
        }

        return Ok(());

    }

}

impl Ofb128 for BlockCipherMode128 {

    fn ofb_encrypt_or_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ofb>::ofb_encrypt_or_decrypt(cipher, sftreg, intext, outtext);
    }

}

impl Ctr for BlockCipherMode128 {

    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipher, ctrblk: &mut [u8], ctrsize: usize,
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {

        let mut b: [u8; 16] = [0; 16];
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

        for i in (0..n).step_by(16) {
            let j: usize = i + 16;
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor(&intext[i..j], &b[..], &mut outtext[i..j], 16);
            increment_counter_block_128(ctrblk, ctrsize);
        }

        if n != len {
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor(&intext[n..len], &b[..], &mut outtext[n..len], len - n);
            increment_counter_block_128(ctrblk, ctrsize);
        }

        return Ok(());

    }

}

impl Ctr128 for BlockCipherMode128 {

    fn ctr_encrypt_or_decrypt(cipher: &(impl BlockCipher + BlockCipher128), ctrblk: &mut [u8],
        ctrsize: usize, intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, ctrblk, ctrsize, intext, outtext);
    }

}

impl Gcm for BlockCipherMode128 {

    fn gcm_encrypt_and_generate(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {

        if plaintext.len() != ciphertext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128   = gcm128_generate_subkey(cipher);
        let mut ctr0: [u8; 16] = [0; 16];
        let mut ctr: [u8; 16]  = [0; 16];

        gcm128_set_counter(&subkey, &iv, &mut ctr0[..]);

        let mut a: usize = 1;
        for i in (0..16).rev() {
            a = a + (ctr0[i] as usize);
            ctr[i] = a as u8;
            a = a >> 8;
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr[..], 4, plaintext, ciphertext)?;
        gcm128_compute_tag(cipher, &subkey, &mut ctr0[..], aad, ciphertext, tag)?;

        return Ok(());

    }

    fn gcm_decrypt_and_verify(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {

        if ciphertext.len() != plaintext.len() || tag.len() != 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let subkey: Block128  = gcm128_generate_subkey(cipher);
        let mut ctr: [u8; 16] = [0; 16];
        let mut tv: [u8; 16]  = [0; 16];

        gcm128_set_counter(&subkey, &iv, &mut ctr[..]);
        gcm128_compute_tag(cipher, &subkey, &mut ctr[..], aad, ciphertext, &mut tv[..])?;

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ tv[i]);
        }
        if s != 0 {
            return Err(CryptoError::new(CryptoErrorCode::VerificationFailed));
        }

        <Self as Ctr>::ctr_encrypt_or_decrypt(cipher, &mut ctr[..], 4, ciphertext, plaintext)?;
        return Ok(true);

    }

}

impl Gcm128 for BlockCipherMode128 {

    fn gcm_encrypt_and_generate(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8],
        aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return <Self as Gcm>::gcm_encrypt_and_generate(cipher, iv, aad, plaintext, ciphertext, tag);
    }

    fn gcm_decrypt_and_verify(cipher: &(impl BlockCipher + BlockCipher128), iv: &[u8], aad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {
        return <Self as Gcm>::gcm_decrypt_and_verify(cipher, iv, aad, ciphertext, plaintext, tag);
    }

}

trait Ecb {
    fn ecb_encrypt_blocks(cipher: &impl BlockCipher, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn ecb_decrypt_blocks(cipher: &impl BlockCipher, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait Cbc {
    fn cbc_encrypt_blocks(cipher: &impl BlockCipher, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_decrypt_blocks(cipher: &impl BlockCipher, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait CbcCts {
    fn cbc_cts_encrypt(cipher: &impl BlockCipher, iv: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cbc_cts_decrypt(cipher: &impl BlockCipher, iv: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb1 {
    fn cfb_fb1_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb1_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb8 {
    fn cfb_fb8_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb8_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait CfbFb128 {
    fn cfb_fb128_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_fb128_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ofb {
    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ctr {
    fn ctr_encrypt_or_decrypt(cipher: &impl BlockCipher, ctrblk: &mut [u8], ctrsize: usize,
        intext: &[u8], outtext: &mut [u8]) -> Result<(), CryptoError>;
}

trait Ccm {
    fn ccm_encrypt_and_generate(cipher: &impl BlockCipher, nonce: &[u8], ad: &[u8],
        plaintext: &[u8], ciphertext: &mut [u8], cbc_mac: &mut [u8]) -> Result<(), CryptoError>;
    fn ccm_decrypt_and_verify(cipher: &impl BlockCipher, nonce: &[u8], ad: &[u8],
        ciphertext: &[u8], plaintext: &mut [u8], cbc_mac: &[u8]) -> Result<bool, CryptoError>;
}

trait Gcm {
    fn gcm_encrypt_and_generate(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError>;
    fn gcm_decrypt_and_verify(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], ciphertext: &[u8],
        plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError>;
}

trait Cmac {
    fn cmac_compute(cipher: &impl BlockCipher, msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}

fn xor(lhs: &[u8], rhs: &[u8], res: &mut [u8], len: usize) {
    for i in 0..len {
        res[i] = lhs[i] ^ rhs[i];
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

struct Block128 {
    l64: u64,
    r64: u64
}

static GCM_R: Block128 = Block128{
    l64: 0xe100000000000000,
    r64: 0x0000000000000000
};

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

fn gcm128_compute_tag(cipher: &impl BlockCipher, subkey: &Block128, ctrblk: &mut [u8],
    aad: &[u8], intext: &[u8], tag: &mut [u8]) -> Result<(), CryptoError> {
    let mut state: Block128 = Block128::from_u64_pair(0, 0);
    gcm128_ghash(subkey, &mut state, aad);
    gcm128_ghash(subkey, &mut state, intext);
    gcm128_ghash_block(
        subkey,
        &mut state,
        &Block128::from_u64_pair((aad.len() as u64) << 3, (intext.len() as u64) << 3)
    );
    return <BlockCipherMode128 as Ctr>::ctr_encrypt_or_decrypt(
        cipher,
        ctrblk,
        0,
        &state.to_bytes()[..],
        tag
    );
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
    cipher.encrypt_and_overwrite_unchecked(&mut h[..]);
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