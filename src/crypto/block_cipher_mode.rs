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
pub trait Cfb128Fb1: Cfb {
    fn cfb_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb8: Cfb {
    fn cfb_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError>;
}

#[allow(private_bounds)]
pub trait Cfb128Fb128: Cfb {
    fn cfb_encrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
        plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_decrypt(cipher: &(impl BlockCipher + BlockCipher128), sftreg: &mut [u8],
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
    fn cmac_generate(cipher: &(impl BlockCipher + BlockCipher128), msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}

pub struct BlockCipherMode128 {}

impl Ecb for BlockCipherMode128 {

    fn ecb_encrypt_blocks(cipher: &impl BlockCipher, plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = plaintext.len();

        if len > ciphertext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            cipher.encrypt_unchecked(&plaintext[i..(i + 16)], &mut ciphertext[i..(i + 16)]);
        }

        return Ok(());

    }

    fn ecb_decrypt_blocks(cipher: &impl BlockCipher, ciphertext: &[u8],
        plaintext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = ciphertext.len();

        if len > plaintext.len() {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        } else if len & 15 != 0 {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIsNotMultipleOfBlockSize));
        }

        for i in (0..len).step_by(16) {
            cipher.decrypt_unchecked(&ciphertext[i..(i + 16)], &mut plaintext[i..(i + 16)]);
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

impl Ofb for BlockCipherMode128 {

    fn ofb_encrypt_or_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], intext: &[u8],
        outtext: &mut [u8]) -> Result<(), CryptoError> {

        let len: usize = intext.len();
        let n: usize = len & usize::MAX.wrapping_shl(4);

        if len > outtext.len() || sftreg.len() < 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        for i in (0..n).step_by(16) {
            cipher.encrypt_and_overwrite_unchecked(sftreg);
            xor(&intext[i..], sftreg, &mut outtext[i..], 16);
        }

        if n != len {
            cipher.encrypt_and_overwrite_unchecked(sftreg);
            xor(&intext[n..], sftreg, &mut outtext[n..], len - n);
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

        if len > outtext.len() || ctrblk.len() < 16 {
            return Err(CryptoError::new(CryptoErrorCode::BufferTooShort));
        } else if ctrsize > 16 {
            return Err(CryptoError::new(CryptoErrorCode::IllegalArgument));
        } else if ctrsize < 8 {
            if ((n >> 4) + (if n != len { 1 } else { 0 })) > (1 << (ctrsize << 3)) {
                return Err(CryptoError::new(CryptoErrorCode::CounterOverwrapped));
            }
        }

        for i in (0..n).step_by(16) {
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor(&intext[i..], &b[..], &mut outtext[i..], 16);
            increment_counter_block(ctrblk, ctrsize);
        }

        if n != len {
            cipher.encrypt_unchecked(&ctrblk[..], &mut b[..]);
            xor(&intext[n..], &b[..], &mut outtext[n..], len - n);
            increment_counter_block(ctrblk, ctrsize);
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

fn increment_counter_block(ctrblk: &mut [u8], ctrsize: usize) {
    let mut a: usize = 1;
    for i in ((ctrsize & 15)..16).rev() {
        a = a + (ctrblk[i] as usize);
        ctrblk[i] = a as u8;
        a = a >> 8;
    }
}

fn xor(lhs: &[u8], rhs: &[u8], res: &mut [u8], len: usize) {
    for i in 0..len {
        res[i] = lhs[i] ^ rhs[i];
    }
}

/*






    fn gcm_encrypt_generate(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], bytes_in: &[u8],
        bytes_out: &mut [u8], tag: &mut [u8]) -> Option<CryptoError> {

        let subkey: Block128   = Self::gcm_generate_subkey(cipher);
        let mut ctr0: [u8; 16] = [0; 16];
        let mut ctr: [u8; 16]  = [0; 16];

        Self::gcm_set_counter(&subkey, &iv, &mut ctr0[..]);

        let mut a: usize = 1;
        for i in (0..16).rev() {
            a = a + (ctr0[i] as usize);
            ctr[i] = a as u8;
            a = a >> 8;
        }

        Self::ctr(cipher, &mut ctr[..], 0, bytes_in, bytes_out);
        Self::gcm_compute_tag(cipher, &subkey, &mut ctr0[..], aad, bytes_in, tag);

        return None;

    }

    fn gcm_decrypt_verify(cipher: &impl BlockCipher, iv: &[u8], aad: &[u8], bytes_in: &[u8],
        bytes_out: &mut [u8], tag: &[u8]) -> Option<CryptoError> {

        let subkey: Block128   = Self::gcm_generate_subkey(cipher);
        let mut ctr: [u8; 16]  = [0; 16];
        let mut tagv: [u8; 16] = [0; 16];

        Self::gcm_set_counter(&subkey, &iv, &mut ctr[..]);
        Self::gcm_compute_tag(cipher, &subkey, &mut ctr[..], aad, bytes_in, &mut tagv[..]);

        let mut s: u8 = 0;
        for i in 0..16 {
            s = s | (tag[i] ^ tagv[i]);
        }

        Self::ctr(cipher, &mut ctr[..], 0, bytes_in, bytes_out);

        return None;

    }

    fn gcm_compute_tag(cipher: &impl BlockCipher, subkey: &Block128, ctr: &mut [u8],
        aad: &[u8], bytes_in: &[u8], tag: &mut [u8]) {
        let mut state: Block128 = Block128::new_as_zero();
        Self::gcm_ghash(subkey, &mut state, aad);
        Self::gcm_ghash(subkey, &mut state, bytes_in);
        Self::gcm_ghash_block(
            subkey,
            &mut state,
            &Block128::from_two_u64s(aad.len() as u64, bytes_in.len() as u64)
        );
        Self::ctr(cipher, ctr, 0, &state.to_be_bytes()[..], tag);
    }

    fn gcm_ghash(subkey: &Block128, state: &mut Block128, bytes_in: &[u8]) {

        let n: usize = bytes_in.len() & usize::MAX.wrapping_shl(4);

        for i in (0..n).step_by(16) {
            let b: Block128 = Block128::from_be_bytes(&bytes_in[i..(i + 16)]);
            Self::gcm_ghash_block(subkey, state, &b);
        }

        if n != bytes_in.len() {
            let b: Block128 = {
                let mut bl: u64  = 0;
                let mut br: u64  = 0;
                let mut i: usize = n;
                let mut s: usize = 64;
                while i < bytes_in.len() && n >= 8 {
                    s = s - 8;
                    bl = bl | ((bytes_in[i] as u64) << s);
                    i = i + 1;
                }
                while i < bytes_in.len() {
                    s = s - 8;
                    br = br | ((bytes_in[i] as u64) << s);
                    i = i + 1;
                }
                Block128::from_two_u64s(bl, br)
            };
            Self::gcm_ghash_block(subkey, state, &b);
        }

    }

    fn gcm_ghash_block(subkey: &Block128, state: &mut Block128, block_in: &Block128) {

        let mut v: Block128 = Block128{
            l64: subkey.l64,
            r64: subkey.r64,
        };

        for i in (0..64).rev() {
            let mask: u64 = 0u64.wrapping_sub((block_in.l64 >> i) & 1);
            state.l64 = state.l64 ^ (v.l64 & mask);
            state.r64 = state.r64 ^ (v.r64 & mask);
            let mask: u64 = 0u64.wrapping_sub((v.r64 >> i) & 1);
            v.r64 = ((v.r64 >> 1) | ((v.l64 & 1) << 63)) ^ (GCM_R.l64 & mask);
            v.l64 =  (v.l64 >> 1)                        ^ (GCM_R.l64 & mask);
        }

        for i in (0..64).rev() {
            let mask: u64 = 0u64.wrapping_sub((block_in.r64 >> i) & 1);
            state.l64 = state.l64 ^ (v.l64 & mask);
            state.r64 = state.r64 ^ (v.r64 & mask);
            let mask: u64 = 0u64.wrapping_sub((v.r64 >> i) & 1);
            v.r64 = ((v.r64 >> 1) | ((v.l64 & 1) << 63)) ^ (GCM_R.l64 & mask);
            v.l64 =  (v.l64 >> 1)                        ^ (GCM_R.l64 & mask);
        }

    }

    fn gcm_generate_subkey(cipher: &impl BlockCipher) -> Block128 {
        let b: [u8; 16]     = [0; 16];
        let mut h: [u8; 16] = [0; 16];
        cipher.encrypt_unchecked(&b, &mut h[..]);
        return Block128::from_be_bytes(&h[..]);
    }

    fn gcm_set_counter(subkey: &Block128, iv: &[u8], counter_block: &mut [u8]) {
        if iv.len() == 12 {
            counter_block[..12].copy_from_slice(&iv[..]);
            counter_block[12] = 0x00;
            counter_block[13] = 0x00;
            counter_block[14] = 0x00;
            counter_block[15] = 0x01;
        } else {
            let mut state: Block128 = Block128::new_as_zero();
            let block: Block128     = Block128::from_two_u64s(0, (iv.len() << 3) as u64);
            Self::gcm_ghash(subkey, &mut state, iv);
            Self::gcm_ghash_block(subkey, &mut state, &block);
            block.copy_to_buf_as_be(counter_block);
        }
    }

}

static GCM_R: Block128 = Block128{
    l64: 0xe100000000000000,
    r64: 0x0000000000000000
};

struct Block128 {
    pub l64: u64,
    pub r64: u64
}

impl Block128 {

    pub fn new_as_zero() -> Self {
        return Self{
            l64: 0,
            r64: 0
        };
    }

    pub fn from_two_u64s(l64: u64, r64: u64) -> Self {
        return Self{
            l64: l64,
            r64: r64
        };
    }

    pub fn try_from_be_bytes(b: &[u8]) -> Self {
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

    pub fn try_into_be_bytes(&self, b: &mut [u8]) {
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

}
    */


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

trait Cfb {
    fn cfb_encrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], plaintext: &[u8],
        ciphertext: &mut [u8]) -> Result<(), CryptoError>;
    fn cfb_decrypt(cipher: &impl BlockCipher, sftreg: &mut [u8], ciphertext: &[u8],
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
    fn cmac_generate(cipher: &impl BlockCipher, msg: &[u8],
        cmac: &mut [u8]) -> Result<(), CryptoError>;
}