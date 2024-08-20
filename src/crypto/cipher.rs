use crate::crypto::CryptoError;

pub trait BlockCipher128 {
    fn encrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn decrypt_unchecked(&self, block_in: &[u8], block_out: &mut [u8]);
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
}

static GCM_R: Block128 = Block128{
    l64: 0xe100000000000000,
    r64: 0x0000000000000000
};

pub struct BlockCipher128Mode;
impl BlockCipher128Mode {

    pub fn ecb_encrypt(cipher: &impl BlockCipher128, bytes_in: &[u8], bytes_out: &mut [u8]) -> Option<CryptoError> {

        let len: usize = bytes_in.len();

        if len > bytes_out.len() {
            return Some(CryptoError::new(""))
        }

        if len & 15 != 0 {
            return Some(CryptoError::new(""));
        }

        for i in (0..len).step_by(16) {
            cipher.encrypt_unchecked(
                &bytes_in[i..(i + 16)],
                &mut bytes_out[i..(i + 16)]
            );
        }

        return None;

    }

    pub fn ecb_decrypt(cipher: &impl BlockCipher128, bytes_in: &[u8], bytes_out: &mut [u8]) -> Option<CryptoError> {

        let len: usize = bytes_in.len();

        if len > bytes_out.len() {
            return Some(CryptoError::new(""))
        }

        if len & 15 != 0 {
            return Some(CryptoError::new(""));
        }

        for i in (0..len).step_by(16) {
            cipher.decrypt_unchecked(
                &bytes_in[i..(i + 16)],
                &mut bytes_out[i..(i + 16)]
            );
        }

        return None;

    }

    pub fn ctr(cipher: &impl BlockCipher128, counter_block: &mut [u8], counter_size: usize,
        bytes_in: &[u8], bytes_out: &mut [u8]) -> Option<CryptoError> {

        if bytes_in.len() > bytes_out.len() {
            return Some(CryptoError::new(""));
        }

        if counter_block.len() < 16 {
            return Some(CryptoError::new(""));
        }

        let mut b: [u8; 16] = [0; 16];
        let n: usize        = (bytes_in.len() & 15) << 4;

        for i in (0..n).step_by(16) {
            cipher.encrypt_unchecked(&counter_block[..], &mut b[..]);
            Self::xor(&bytes_in[i..], &b[..], &mut bytes_out[i..], 16);
            Self::increment_counter_block_by_one(counter_block, counter_size);
        }

        if n != bytes_in.len() {
            cipher.encrypt_unchecked(&counter_block[..], &mut b[..]);
            Self::xor(&bytes_in[n..], &b[..], &mut bytes_out[n..], bytes_in.len() - n);
            Self::increment_counter_block_by_one(counter_block, counter_size);
        }

        return None;

    }

    fn increment_counter_block_by_one(counter_block: &mut [u8], counter_size: usize) {
        let mut a: usize = 1;
        for i in (counter_size..16).rev() {
            a = a + (counter_block[i] as usize);
            counter_block[i] = a as u8;
            a = a >> 8;
        }
    }

    fn xor(lhs: &[u8], rhs: &[u8], out: &mut [u8], len: usize) {
        for i in 0..len {
            out[i] = lhs[i] ^ rhs[i];
        }
    }

    fn gcm_encrypt_generate(cipher: &impl BlockCipher128, iv: &[u8], aad: &[u8], bytes_in: &[u8],
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

    fn gcm_decrypt_verify(cipher: &impl BlockCipher128, iv: &[u8], aad: &[u8], bytes_in: &[u8],
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

    fn gcm_compute_tag(cipher: &impl BlockCipher128, subkey: &Block128, ctr: &mut [u8],
        aad: &[u8], bytes_in: &[u8], tag: &mut [u8]) {
        let mut state: Block128 = Block128::as_zero();
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

    fn gcm_generate_subkey(cipher: &impl BlockCipher128) -> Block128 {
        let b: [u8; 16]     = [0; 16];
        let mut h: [u8; 16] = [0; 16];
        cipher.encrypt_unchecked(&b, &mut h[..]);
        return Block128::from_be_bytes(&h[..]);
    }

    fn gcm_set_counter(subkey: &Block128, iv: &[u8], counter_block: &mut [u8]) {
        if iv.len() == 12 {
            counter_block[..12].clone_from_slice(&iv[..]);
            counter_block[12] = 0x00;
            counter_block[13] = 0x00;
            counter_block[14] = 0x00;
            counter_block[15] = 0x01;
        } else {
            let mut state: Block128 = Block128::as_zero();
            let block: Block128     = Block128::from_two_u64s(0, (iv.len() << 3) as u64);
            Self::gcm_ghash(subkey, &mut state, iv);
            Self::gcm_ghash_block(subkey, &mut state, &block);
            block.copy_to_buf_as_be(counter_block);
        }
    }

}

struct Block128 {
    pub l64: u64,
    pub r64: u64
}

impl Block128 {

    pub fn as_zero() -> Self {
        return Self{
            l64: 0,
            r64: 0
        };
    }

    pub fn from_two_u64s(left: u64, right: u64) -> Self {
        return Self{
            l64: left,
            r64: right
        };
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        return Self{
            l64: {
                ((bytes[ 0] as u64) << 56) |
                ((bytes[ 1] as u64) << 48) |
                ((bytes[ 2] as u64) << 40) |
                ((bytes[ 3] as u64) << 32) |
                ((bytes[ 4] as u64) << 24) |
                ((bytes[ 5] as u64) << 16) |
                ((bytes[ 6] as u64) <<  8) |
                  bytes[ 7] as u64
            },
            r64: {
                ((bytes[ 8] as u64) << 56) |
                ((bytes[ 9] as u64) << 48) |
                ((bytes[10] as u64) << 40) |
                ((bytes[11] as u64) << 32) |
                ((bytes[12] as u64) << 24) |
                ((bytes[13] as u64) << 16) |
                ((bytes[14] as u64) <<  8) |
                  bytes[15] as u64
            }
        };
    }

    pub fn copy_to_buf_as_be(&self, buf: &mut [u8]) {
        buf[ 0] = (self.l64 >> 56) as u8;
        buf[ 1] = (self.l64 >> 48) as u8;
        buf[ 2] = (self.l64 >> 40) as u8;
        buf[ 3] = (self.l64 >> 32) as u8;
        buf[ 4] = (self.l64 >> 24) as u8;
        buf[ 5] = (self.l64 >> 16) as u8;
        buf[ 6] = (self.l64 >>  8) as u8;
        buf[ 7] =  self.l64        as u8;
        buf[ 8] = (self.r64 >> 56) as u8;
        buf[ 9] = (self.r64 >> 48) as u8;
        buf[10] = (self.r64 >> 40) as u8;
        buf[11] = (self.r64 >> 32) as u8;
        buf[12] = (self.r64 >> 24) as u8;
        buf[13] = (self.r64 >> 16) as u8;
        buf[14] = (self.r64 >>  8) as u8;
        buf[15] =  self.r64        as u8;
    }

    pub fn to_be_bytes(&self) -> [u8; 16] {
        let mut bytes: [u8; 16] = [0; 16];
        self.copy_to_buf_as_be(&mut bytes);
        return bytes;
    }

}