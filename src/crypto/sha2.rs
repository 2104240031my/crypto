use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::Hash;

pub struct Sha224 {
    s: Sha2State32
}

pub struct Sha256 {
    s: Sha2State32
}

pub struct Sha384 {
    s: Sha2State64
}

pub struct Sha512 {
    s: Sha2State64
}

pub struct Sha512224 {
    s: Sha2State64
}

pub struct Sha512256 {
    s: Sha2State64
}

impl Sha224 {

    const H0_0: u32 = 0xc1059ed8;
    const H0_1: u32 = 0x367cd507;
    const H0_2: u32 = 0x3070dd17;
    const H0_3: u32 = 0xf70e5939;
    const H0_4: u32 = 0xffc00b31;
    const H0_5: u32 = 0x68581511;
    const H0_6: u32 = 0x64f98fa7;
    const H0_7: u32 = 0xbefa4fa4;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State32{
                h: [
                    Sha224::H0_0,
                    Sha224::H0_1,
                    Sha224::H0_2,
                    Sha224::H0_3,
                    Sha224::H0_4,
                    Sha224::H0_5,
                    Sha224::H0_6,
                    Sha224::H0_7
                ],
                buf: [0; 128],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha224::H0_0;
        self.s.h[1] = Sha224::H0_1;
        self.s.h[2] = Sha224::H0_2;
        self.s.h[3] = Sha224::H0_3;
        self.s.h[4] = Sha224::H0_4;
        self.s.h[5] = Sha224::H0_5;
        self.s.h[6] = Sha224::H0_6;
        self.s.h[7] = Sha224::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha224 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA224_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State32 = Sha2State32{
            h: [
                Sha224::H0_0,
                Sha224::H0_1,
                Sha224::H0_2,
                Sha224::H0_3,
                Sha224::H0_4,
                Sha224::H0_5,
                Sha224::H0_6,
                Sha224::H0_7
            ],
            buf: [0; 128],
            buf_len: 0,
            total_len: 0
        };

        sha2_32_digest_oneshot(&mut s, msg);

        for i in 0..7 {
            let d: usize = i << 2;
            md[d + 0] = (s.h[i] >> 24) as u8;
            md[d + 1] = (s.h[i] >> 16) as u8;
            md[d + 2] = (s.h[i] >>  8) as u8;
            md[d + 3] =  s.h[i]        as u8;
        }

        return None;

    }

    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_32_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA224_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u32; 8] = [0; 8];
        sha2_32_digest(&mut self.s, &mut h[..]);

        for i in 0..7 {
            let d: usize = i << 2;
            md[d + 0] = (h[i] >> 24) as u8;
            md[d + 1] = (h[i] >> 16) as u8;
            md[d + 2] = (h[i] >>  8) as u8;
            md[d + 3] =  h[i]        as u8;
        }

        return None;

    }

}

impl Sha256 {

    const H0_0: u32 = 0x6a09e667;
    const H0_1: u32 = 0xbb67ae85;
    const H0_2: u32 = 0x3c6ef372;
    const H0_3: u32 = 0xa54ff53a;
    const H0_4: u32 = 0x510e527f;
    const H0_5: u32 = 0x9b05688c;
    const H0_6: u32 = 0x1f83d9ab;
    const H0_7: u32 = 0x5be0cd19;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State32{
                h: [
                    Sha256::H0_0,
                    Sha256::H0_1,
                    Sha256::H0_2,
                    Sha256::H0_3,
                    Sha256::H0_4,
                    Sha256::H0_5,
                    Sha256::H0_6,
                    Sha256::H0_7
                ],
                buf: [0; 128],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha256::H0_0;
        self.s.h[1] = Sha256::H0_1;
        self.s.h[2] = Sha256::H0_2;
        self.s.h[3] = Sha256::H0_3;
        self.s.h[4] = Sha256::H0_4;
        self.s.h[5] = Sha256::H0_5;
        self.s.h[6] = Sha256::H0_6;
        self.s.h[7] = Sha256::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha256 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA256_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State32 = Sha2State32{
            h: [
                Sha256::H0_0,
                Sha256::H0_1,
                Sha256::H0_2,
                Sha256::H0_3,
                Sha256::H0_4,
                Sha256::H0_5,
                Sha256::H0_6,
                Sha256::H0_7
            ],
            buf: [0; 128],
            buf_len: 0,
            total_len: 0
        };

        sha2_32_digest_oneshot(&mut s, msg);

        for i in 0..8 {
            let d: usize = i << 2;
            md[d + 0] = (s.h[i] >> 24) as u8;
            md[d + 1] = (s.h[i] >> 16) as u8;
            md[d + 2] = (s.h[i] >>  8) as u8;
            md[d + 3] =  s.h[i]        as u8;
        }

        return None;

    }


    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_32_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA256_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u32; 8] = [0; 8];
        sha2_32_digest(&mut self.s, &mut h[..]);

        for i in 0..8 {
            let d: usize = i << 2;
            md[d + 0] = (h[i] >> 24) as u8;
            md[d + 1] = (h[i] >> 16) as u8;
            md[d + 2] = (h[i] >>  8) as u8;
            md[d + 3] =  h[i]        as u8;
        }

        return None;

    }

}

impl Sha384 {

    const H0_0: u64 = 0xcbbb9d5dc1059ed8;
    const H0_1: u64 = 0x629a292a367cd507;
    const H0_2: u64 = 0x9159015a3070dd17;
    const H0_3: u64 = 0x152fecd8f70e5939;
    const H0_4: u64 = 0x67332667ffc00b31;
    const H0_5: u64 = 0x8eb44a8768581511;
    const H0_6: u64 = 0xdb0c2e0d64f98fa7;
    const H0_7: u64 = 0x47b5481dbefa4fa4;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State64{
                h: [
                    Sha384::H0_0,
                    Sha384::H0_1,
                    Sha384::H0_2,
                    Sha384::H0_3,
                    Sha384::H0_4,
                    Sha384::H0_5,
                    Sha384::H0_6,
                    Sha384::H0_7
                ],
                buf: [0; 256],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha384::H0_0;
        self.s.h[1] = Sha384::H0_1;
        self.s.h[2] = Sha384::H0_2;
        self.s.h[3] = Sha384::H0_3;
        self.s.h[4] = Sha384::H0_4;
        self.s.h[5] = Sha384::H0_5;
        self.s.h[6] = Sha384::H0_6;
        self.s.h[7] = Sha384::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha384 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA384_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State64 = Sha2State64{
            h: [
                Sha384::H0_0,
                Sha384::H0_1,
                Sha384::H0_2,
                Sha384::H0_3,
                Sha384::H0_4,
                Sha384::H0_5,
                Sha384::H0_6,
                Sha384::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut s, msg);

        for i in 0..6 {
            let d: usize = i << 3;
            md[d + 0] = (s.h[i] >> 56) as u8;
            md[d + 1] = (s.h[i] >> 48) as u8;
            md[d + 2] = (s.h[i] >> 40) as u8;
            md[d + 3] = (s.h[i] >> 32) as u8;
            md[d + 4] = (s.h[i] >> 24) as u8;
            md[d + 5] = (s.h[i] >> 16) as u8;
            md[d + 6] = (s.h[i] >>  8) as u8;
            md[d + 7] =  s.h[i]        as u8;
        }

        return None;

    }

    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_64_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA384_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u64; 8] = [0; 8];
        sha2_64_digest(&mut self.s, &mut h[..]);

        for i in 0..6 {
            let d: usize = i << 3;
            md[d + 0] = (h[i] >> 56) as u8;
            md[d + 1] = (h[i] >> 48) as u8;
            md[d + 2] = (h[i] >> 40) as u8;
            md[d + 3] = (h[i] >> 32) as u8;
            md[d + 4] = (h[i] >> 24) as u8;
            md[d + 5] = (h[i] >> 16) as u8;
            md[d + 6] = (h[i] >>  8) as u8;
            md[d + 7] =  h[i]        as u8;
        }

        return None;

    }

}

impl Sha512 {

    const H0_0: u64 = 0x6a09e667f3bcc908;
    const H0_1: u64 = 0xbb67ae8584caa73b;
    const H0_2: u64 = 0x3c6ef372fe94f82b;
    const H0_3: u64 = 0xa54ff53a5f1d36f1;
    const H0_4: u64 = 0x510e527fade682d1;
    const H0_5: u64 = 0x9b05688c2b3e6c1f;
    const H0_6: u64 = 0x1f83d9abfb41bd6b;
    const H0_7: u64 = 0x5be0cd19137e2179;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State64{
                h: [
                    Sha512::H0_0,
                    Sha512::H0_1,
                    Sha512::H0_2,
                    Sha512::H0_3,
                    Sha512::H0_4,
                    Sha512::H0_5,
                    Sha512::H0_6,
                    Sha512::H0_7
                ],
                buf: [0; 256],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha512::H0_0;
        self.s.h[1] = Sha512::H0_1;
        self.s.h[2] = Sha512::H0_2;
        self.s.h[3] = Sha512::H0_3;
        self.s.h[4] = Sha512::H0_4;
        self.s.h[5] = Sha512::H0_5;
        self.s.h[6] = Sha512::H0_6;
        self.s.h[7] = Sha512::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha512 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State64 = Sha2State64{
            h: [
                Sha512::H0_0,
                Sha512::H0_1,
                Sha512::H0_2,
                Sha512::H0_3,
                Sha512::H0_4,
                Sha512::H0_5,
                Sha512::H0_6,
                Sha512::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut s, msg);

        for i in 0..8 {
            let d: usize = i << 3;
            md[d + 0] = (s.h[i] >> 56) as u8;
            md[d + 1] = (s.h[i] >> 48) as u8;
            md[d + 2] = (s.h[i] >> 40) as u8;
            md[d + 3] = (s.h[i] >> 32) as u8;
            md[d + 4] = (s.h[i] >> 24) as u8;
            md[d + 5] = (s.h[i] >> 16) as u8;
            md[d + 6] = (s.h[i] >>  8) as u8;
            md[d + 7] =  s.h[i]        as u8;
        }

        return None;

    }

    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_64_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u64; 8] = [0; 8];
        sha2_64_digest(&mut self.s, &mut h[..]);

        for i in 0..8 {
            let d: usize = i << 3;
            md[d + 0] = (h[i] >> 56) as u8;
            md[d + 1] = (h[i] >> 48) as u8;
            md[d + 2] = (h[i] >> 40) as u8;
            md[d + 3] = (h[i] >> 32) as u8;
            md[d + 4] = (h[i] >> 24) as u8;
            md[d + 5] = (h[i] >> 16) as u8;
            md[d + 6] = (h[i] >>  8) as u8;
            md[d + 7] =  h[i]        as u8;
        }

        return None;

    }

}

impl Sha512224 {

    const H0_0: u64 = 0x8c3d37c819544da2;
    const H0_1: u64 = 0x73e1996689dcd4d6;
    const H0_2: u64 = 0x1dfab7ae32ff9c82;
    const H0_3: u64 = 0x679dd514582f9fcf;
    const H0_4: u64 = 0x0f6d2b697bd44da8;
    const H0_5: u64 = 0x77e36f7304c48942;
    const H0_6: u64 = 0x3f9d85a86a1d36c8;
    const H0_7: u64 = 0x1112e6ad91d692a1;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State64{
                h: [
                    Sha512224::H0_0,
                    Sha512224::H0_1,
                    Sha512224::H0_2,
                    Sha512224::H0_3,
                    Sha512224::H0_4,
                    Sha512224::H0_5,
                    Sha512224::H0_6,
                    Sha512224::H0_7
                ],
                buf: [0; 256],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha512224::H0_0;
        self.s.h[1] = Sha512224::H0_1;
        self.s.h[2] = Sha512224::H0_2;
        self.s.h[3] = Sha512224::H0_3;
        self.s.h[4] = Sha512224::H0_4;
        self.s.h[5] = Sha512224::H0_5;
        self.s.h[6] = Sha512224::H0_6;
        self.s.h[7] = Sha512224::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha512224 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512224_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State64 = Sha2State64{
            h: [
                Sha512224::H0_0,
                Sha512224::H0_1,
                Sha512224::H0_2,
                Sha512224::H0_3,
                Sha512224::H0_4,
                Sha512224::H0_5,
                Sha512224::H0_6,
                Sha512224::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut s, msg);

        let mut i: usize = 0;
        loop {
            let d: usize = i << 3;
            md[d + 0] = (s.h[i] >> 56) as u8;
            md[d + 1] = (s.h[i] >> 48) as u8;
            md[d + 2] = (s.h[i] >> 40) as u8;
            md[d + 3] = (s.h[i] >> 32) as u8;
            if i >= 3 {
                break;
            }
            md[d + 4] = (s.h[i] >> 24) as u8;
            md[d + 5] = (s.h[i] >> 16) as u8;
            md[d + 6] = (s.h[i] >>  8) as u8;
            md[d + 7] =  s.h[i]        as u8;
            i = i + 1;
        }

        return None;

    }

    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_64_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512224_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u64; 8] = [0; 8];
        sha2_64_digest(&mut self.s, &mut h[..]);

        let mut i: usize = 0;
        loop {
            let d: usize = i << 3;
            md[d + 0] = (h[i] >> 56) as u8;
            md[d + 1] = (h[i] >> 48) as u8;
            md[d + 2] = (h[i] >> 40) as u8;
            md[d + 3] = (h[i] >> 32) as u8;
            if i >= 3 {
                break;
            }
            md[d + 4] = (h[i] >> 24) as u8;
            md[d + 5] = (h[i] >> 16) as u8;
            md[d + 6] = (h[i] >>  8) as u8;
            md[d + 7] =  h[i]        as u8;
            i = i + 1;
        }

        return None;

    }

}

impl Sha512256 {

    const H0_0: u64 = 0x22312194fc2bf72c;
    const H0_1: u64 = 0x9f555fa3c84c64c2;
    const H0_2: u64 = 0x2393b86b6f53b151;
    const H0_3: u64 = 0x963877195940eabd;
    const H0_4: u64 = 0x96283ee2a88effe3;
    const H0_5: u64 = 0xbe5e1e2553863992;
    const H0_6: u64 = 0x2b0199fc2c85b8aa;
    const H0_7: u64 = 0x0eb72ddc81c52ca2;

    pub fn new() -> Self {
        return Self{ s:
            Sha2State64{
                h: [
                    Sha512256::H0_0,
                    Sha512256::H0_1,
                    Sha512256::H0_2,
                    Sha512256::H0_3,
                    Sha512256::H0_4,
                    Sha512256::H0_5,
                    Sha512256::H0_6,
                    Sha512256::H0_7
                ],
                buf: [0; 256],
                buf_len: 0,
                total_len: 0
            }
        };
    }

    pub fn reset(&mut self) {
        self.s.h[0] = Sha512256::H0_0;
        self.s.h[1] = Sha512256::H0_1;
        self.s.h[2] = Sha512256::H0_2;
        self.s.h[3] = Sha512256::H0_3;
        self.s.h[4] = Sha512256::H0_4;
        self.s.h[5] = Sha512256::H0_5;
        self.s.h[6] = Sha512256::H0_6;
        self.s.h[7] = Sha512256::H0_7;
        self.s.buf_len = 0;
        self.s.total_len = 0;
    }

}

impl Hash for Sha512256 {

    fn digest_oneshot(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512256_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut s: Sha2State64 = Sha2State64{
            h: [
                Sha512256::H0_0,
                Sha512256::H0_1,
                Sha512256::H0_2,
                Sha512256::H0_3,
                Sha512256::H0_4,
                Sha512256::H0_5,
                Sha512256::H0_6,
                Sha512256::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut s, msg);

        for i in 0..4 {
            let d: usize = i << 3;
            md[d + 0] = (s.h[i] >> 56) as u8;
            md[d + 1] = (s.h[i] >> 48) as u8;
            md[d + 2] = (s.h[i] >> 40) as u8;
            md[d + 3] = (s.h[i] >> 32) as u8;
            md[d + 4] = (s.h[i] >> 24) as u8;
            md[d + 5] = (s.h[i] >> 16) as u8;
            md[d + 6] = (s.h[i] >>  8) as u8;
            md[d + 7] =  s.h[i]        as u8;
        }

        return None;

    }

    fn update(&mut self, msg: &[u8]) -> Option<CryptoError> {
        sha2_64_update(&mut self.s, msg);
        return None;
    }

    fn digest(&mut self, md: &mut [u8]) -> Option<CryptoError> {

        if md.len() < SHA512256_DIGEST_LEN {
            return Some(CryptoError::new(CryptoErrorCode::BufferTooShort));
        }

        let mut h: [u64; 8] = [0; 8];
        sha2_64_digest(&mut self.s, &mut h[..]);

        for i in 0..4 {
            let d: usize = i << 3;
            md[d + 0] = (h[i] >> 56) as u8;
            md[d + 1] = (h[i] >> 48) as u8;
            md[d + 2] = (h[i] >> 40) as u8;
            md[d + 3] = (h[i] >> 32) as u8;
            md[d + 4] = (h[i] >> 24) as u8;
            md[d + 5] = (h[i] >> 16) as u8;
            md[d + 6] = (h[i] >>  8) as u8;
            md[d + 7] =  h[i]        as u8;
        }

        return None;

    }

}

static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

static K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

const SHA224_DIGEST_LEN: usize = 28;
const SHA256_DIGEST_LEN: usize = 32;
const SHA384_DIGEST_LEN: usize = 48;
const SHA512_DIGEST_LEN: usize = 64;
const SHA512224_DIGEST_LEN: usize = 28;
const SHA512256_DIGEST_LEN: usize = 32;

const SHA2_32_BLOCK_LEN: usize = 64;
const SHA2_64_BLOCK_LEN: usize = 128;

struct Sha2State32 {
    h: [u32; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: usize
}

struct Sha2State64 {
    h: [u64; 8],
    buf: [u8; 256],
    buf_len: usize,
    total_len: usize
}

fn sha2_32_digest_oneshot(s: &mut Sha2State32, msg: &[u8]) {

    let mut w: [u32; 64] = [0; 64];
    let mut i: usize     = 0;

    for _ in ((msg.len() >> 6)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((msg[i + 0] as u32) << 24) |
                ((msg[i + 1] as u32) << 16) |
                ((msg[i + 2] as u32) <<  8) |
                 (msg[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = s.h[0];
        let mut b: u32 = s.h[1];
        let mut c: u32 = s.h[2];
        let mut d: u32 = s.h[3];
        let mut e: u32 = s.h[4];
        let mut f: u32 = s.h[5];
        let mut g: u32 = s.h[6];
        let mut h: u32 = s.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

    let n: usize = {
        let n: usize = 64 - (msg.len() & 63);
        let n: usize = n + (if n < 9 { 64 } else { 0 });
        n + ((64 - (n & 63)) & 63)
    };

    s.buf[..(msg.len() - i)].clone_from_slice(&msg[i..(msg.len())]);
    s.buf[msg.len() - i] = 0x80;

    let bit_len: u64 = (msg.len() as u64) << 3;
    s.buf[n - 8] = (bit_len >> 56) as u8;
    s.buf[n - 7] = (bit_len >> 48) as u8;
    s.buf[n - 6] = (bit_len >> 40) as u8;
    s.buf[n - 5] = (bit_len >> 32) as u8;
    s.buf[n - 4] = (bit_len >> 24) as u8;
    s.buf[n - 3] = (bit_len >> 16) as u8;
    s.buf[n - 2] = (bit_len >>  8) as u8;
    s.buf[n - 1] =  bit_len        as u8;

    i = 0;

    for _ in 0..(n >> 6) {

        for t in 0..16 {
            w[t] =
                ((s.buf[i + 0] as u32) << 24) |
                ((s.buf[i + 1] as u32) << 16) |
                ((s.buf[i + 2] as u32) <<  8) |
                 (s.buf[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = s.h[0];
        let mut b: u32 = s.h[1];
        let mut c: u32 = s.h[2];
        let mut d: u32 = s.h[3];
        let mut e: u32 = s.h[4];
        let mut f: u32 = s.h[5];
        let mut g: u32 = s.h[6];
        let mut h: u32 = s.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

}

fn sha2_32_update(s: &mut Sha2State32, msg: &[u8]) {

    if msg.len() < SHA2_32_BLOCK_LEN - s.buf_len {
        s.buf[(s.buf_len)..(s.buf_len + msg.len())].clone_from_slice(&msg[..]);
        s.buf_len = s.buf_len + msg.len();
        return;
    }

    let mut w: [u32; 64] = [0; 64];
    let mut i: usize = if s.buf_len == 0 { 0 } else { SHA2_32_BLOCK_LEN - s.buf_len };

    if i != 0 {

        s.buf[(s.buf_len)..i].clone_from_slice(&msg[..i]);

        for t in 0..16 {
            let j = i << 2;
            w[t] =
                ((s.buf[j + 0] as u32) << 24) |
                ((s.buf[j + 1] as u32) << 16) |
                ((s.buf[j + 2] as u32) <<  8) |
                 (s.buf[j + 3] as u32);
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = s.h[0];
        let mut b: u32 = s.h[1];
        let mut c: u32 = s.h[2];
        let mut d: u32 = s.h[3];
        let mut e: u32 = s.h[4];
        let mut f: u32 = s.h[5];
        let mut g: u32 = s.h[6];
        let mut h: u32 = s.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

        s.total_len = s.total_len + s.buf_len;

    }

    for _ in (((msg.len() - i) >> 6)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((msg[i + 0] as u32) << 24) |
                ((msg[i + 1] as u32) << 16) |
                ((msg[i + 2] as u32) <<  8) |
                 (msg[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = s.h[0];
        let mut b: u32 = s.h[1];
        let mut c: u32 = s.h[2];
        let mut d: u32 = s.h[3];
        let mut e: u32 = s.h[4];
        let mut f: u32 = s.h[5];
        let mut g: u32 = s.h[6];
        let mut h: u32 = s.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

    if i < msg.len() {
        s.buf_len = msg.len() - i;
        s.buf[..(s.buf_len)].clone_from_slice(&msg[i..(i + s.buf_len)]);
    } else {
        s.buf_len = 0;
    }

}

fn sha2_32_digest(s: &mut Sha2State32, out: &mut [u32]) {

    out[0] = s.h[0];
    out[1] = s.h[1];
    out[2] = s.h[2];
    out[3] = s.h[3];
    out[4] = s.h[4];
    out[5] = s.h[5];
    out[6] = s.h[6];
    out[7] = s.h[7];

    let n: usize = {
        let n: usize = 64 - ((s.total_len + s.buf_len) & 63);
        let n: usize = n + (if n < 9 { 64 } else { 0 });
        n + ((64 - (n & 63)) & 63)
    };

    s.buf[s.buf_len] = 0x80;

    for i in (s.buf_len + 1)..(n - 8) {
        s.buf[i] = 0x00;
    }

    let bit_len: u64 = ((s.total_len + s.buf_len) as u64) << 3;
    s.buf[n - 8] = (bit_len >> 56) as u8;
    s.buf[n - 7] = (bit_len >> 48) as u8;
    s.buf[n - 6] = (bit_len >> 40) as u8;
    s.buf[n - 5] = (bit_len >> 32) as u8;
    s.buf[n - 4] = (bit_len >> 24) as u8;
    s.buf[n - 3] = (bit_len >> 16) as u8;
    s.buf[n - 2] = (bit_len >>  8) as u8;
    s.buf[n - 1] =  bit_len        as u8;

    let mut w: [u32; 64] = [0; 64];
    let mut i: usize     = 0;

    for _ in 0..(n >> 6) {

        for t in 0..16 {
            w[t] =
                ((s.buf[i + 0] as u32) << 24) |
                ((s.buf[i + 1] as u32) << 16) |
                ((s.buf[i + 2] as u32) <<  8) |
                 (s.buf[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = out[0];
        let mut b: u32 = out[1];
        let mut c: u32 = out[2];
        let mut d: u32 = out[3];
        let mut e: u32 = out[4];
        let mut f: u32 = out[5];
        let mut g: u32 = out[6];
        let mut h: u32 = out[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        out[0] = out[0].wrapping_add(a);
        out[1] = out[1].wrapping_add(b);
        out[2] = out[2].wrapping_add(c);
        out[3] = out[3].wrapping_add(d);
        out[4] = out[4].wrapping_add(e);
        out[5] = out[5].wrapping_add(f);
        out[6] = out[6].wrapping_add(g);
        out[7] = out[7].wrapping_add(h);

    }

}

fn sha2_64_digest_oneshot(s: &mut Sha2State64, msg: &[u8]) {

    let mut w: [u64; 80] = [0; 80];
    let mut i: usize = 0;

    for _ in ((msg.len() >> 7)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((msg[i + 0] as u64) << 56) |
                ((msg[i + 1] as u64) << 48) |
                ((msg[i + 2] as u64) << 40) |
                ((msg[i + 3] as u64) << 32) |
                ((msg[i + 4] as u64) << 24) |
                ((msg[i + 5] as u64) << 16) |
                ((msg[i + 6] as u64) <<  8) |
                 (msg[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = s.h[0];
        let mut b: u64 = s.h[1];
        let mut c: u64 = s.h[2];
        let mut d: u64 = s.h[3];
        let mut e: u64 = s.h[4];
        let mut f: u64 = s.h[5];
        let mut g: u64 = s.h[6];
        let mut h: u64 = s.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

    let n: usize = {
        let n: usize = 128 - (msg.len() & 127);
        let n: usize = n + (if n < 17 { 128 } else { 0 });
        n + ((128 - (n & 127)) & 127)
    };

    s.buf[..(msg.len() - i)].clone_from_slice(&msg[i..(msg.len())]);
    s.buf[msg.len() - i] = 0x80;

    let bit_len: u64 = (msg.len() as u64) << 3;
    s.buf[n - 8] = (bit_len >> 56) as u8;
    s.buf[n - 7] = (bit_len >> 48) as u8;
    s.buf[n - 6] = (bit_len >> 40) as u8;
    s.buf[n - 5] = (bit_len >> 32) as u8;
    s.buf[n - 4] = (bit_len >> 24) as u8;
    s.buf[n - 3] = (bit_len >> 16) as u8;
    s.buf[n - 2] = (bit_len >>  8) as u8;
    s.buf[n - 1] =  bit_len        as u8;

    i = 0;

    for _ in 0..(n >> 7) {

        for t in 0..16 {
            w[t] =
                ((s.buf[i + 0] as u64) << 56) |
                ((s.buf[i + 1] as u64) << 48) |
                ((s.buf[i + 2] as u64) << 40) |
                ((s.buf[i + 3] as u64) << 32) |
                ((s.buf[i + 4] as u64) << 24) |
                ((s.buf[i + 5] as u64) << 16) |
                ((s.buf[i + 6] as u64) <<  8) |
                 (s.buf[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = s.h[0];
        let mut b: u64 = s.h[1];
        let mut c: u64 = s.h[2];
        let mut d: u64 = s.h[3];
        let mut e: u64 = s.h[4];
        let mut f: u64 = s.h[5];
        let mut g: u64 = s.h[6];
        let mut h: u64 = s.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

}

fn sha2_64_update(s: &mut Sha2State64, msg: &[u8]) {

    if msg.len() < SHA2_64_BLOCK_LEN - s.buf_len {
        s.buf[(s.buf_len)..(s.buf_len + msg.len())].clone_from_slice(&msg[..]);
        s.buf_len = s.buf_len + msg.len();
        return;
    }

    let mut w: [u64; 80] = [0; 80];
    let mut i: usize = if s.buf_len == 0 { 0 } else { SHA2_64_BLOCK_LEN - s.buf_len };

    if i != 0 {

        s.buf[(s.buf_len)..i].clone_from_slice(&msg[..i]);

        for t in 0..16 {
            let j = i << 3;
            w[t] =
                ((s.buf[j + 0] as u64) << 56) |
                ((s.buf[j + 1] as u64) << 48) |
                ((s.buf[j + 2] as u64) << 40) |
                ((s.buf[j + 3] as u64) << 32) |
                ((s.buf[j + 4] as u64) << 24) |
                ((s.buf[j + 5] as u64) << 16) |
                ((s.buf[j + 6] as u64) <<  8) |
                 (s.buf[j + 7] as u64);
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = s.h[0];
        let mut b: u64 = s.h[1];
        let mut c: u64 = s.h[2];
        let mut d: u64 = s.h[3];
        let mut e: u64 = s.h[4];
        let mut f: u64 = s.h[5];
        let mut g: u64 = s.h[6];
        let mut h: u64 = s.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

        s.total_len = s.total_len + s.buf_len;

    }

    for _ in (((msg.len() - i) >> 7)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((msg[i + 0] as u64) << 56) |
                ((msg[i + 1] as u64) << 48) |
                ((msg[i + 2] as u64) << 40) |
                ((msg[i + 3] as u64) << 32) |
                ((msg[i + 4] as u64) << 24) |
                ((msg[i + 5] as u64) << 16) |
                ((msg[i + 6] as u64) <<  8) |
                 (msg[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = s.h[0];
        let mut b: u64 = s.h[1];
        let mut c: u64 = s.h[2];
        let mut d: u64 = s.h[3];
        let mut e: u64 = s.h[4];
        let mut f: u64 = s.h[5];
        let mut g: u64 = s.h[6];
        let mut h: u64 = s.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
        s.h[5] = s.h[5].wrapping_add(f);
        s.h[6] = s.h[6].wrapping_add(g);
        s.h[7] = s.h[7].wrapping_add(h);

    }

    if i < msg.len() {
        s.buf_len = msg.len() - i;
        s.buf[..(s.buf_len)].clone_from_slice(&msg[i..(i + s.buf_len)]);
    } else {
        s.buf_len = 0;
    }

}

fn sha2_64_digest(s: &mut Sha2State64, out: &mut [u64]) {

    out[0] = s.h[0];
    out[1] = s.h[1];
    out[2] = s.h[2];
    out[3] = s.h[3];
    out[4] = s.h[4];
    out[5] = s.h[5];
    out[6] = s.h[6];
    out[7] = s.h[7];

    let n: usize = {
        let n: usize = 128 - ((s.total_len + s.buf_len) & 127);
        let n: usize = n + (if n < 17 { 128 } else { 0 });
        n + ((128 - (n & 127)) & 127)
    };

    s.buf[s.buf_len] = 0x80;

    for i in (s.buf_len + 1)..(n - 8) {
        s.buf[i] = 0x00;
    }

    let bit_len: u64 = ((s.total_len + s.buf_len) as u64) << 3;
    s.buf[n - 8] = (bit_len >> 56) as u8;
    s.buf[n - 7] = (bit_len >> 48) as u8;
    s.buf[n - 6] = (bit_len >> 40) as u8;
    s.buf[n - 5] = (bit_len >> 32) as u8;
    s.buf[n - 4] = (bit_len >> 24) as u8;
    s.buf[n - 3] = (bit_len >> 16) as u8;
    s.buf[n - 2] = (bit_len >>  8) as u8;
    s.buf[n - 1] =  bit_len        as u8;

    let mut w: [u64; 80] = [0; 80];
    let mut i: usize     = 0;

    for _ in 0..(n >> 7) {

        for t in 0..16 {
            w[t] =
                ((s.buf[i + 0] as u64) << 56) |
                ((s.buf[i + 1] as u64) << 48) |
                ((s.buf[i + 2] as u64) << 40) |
                ((s.buf[i + 3] as u64) << 32) |
                ((s.buf[i + 4] as u64) << 24) |
                ((s.buf[i + 5] as u64) << 16) |
                ((s.buf[i + 6] as u64) <<  8) |
                 (s.buf[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = out[0];
        let mut b: u64 = out[1];
        let mut c: u64 = out[2];
        let mut d: u64 = out[3];
        let mut e: u64 = out[4];
        let mut f: u64 = out[5];
        let mut g: u64 = out[6];
        let mut h: u64 = out[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        out[0] = out[0].wrapping_add(a);
        out[1] = out[1].wrapping_add(b);
        out[2] = out[2].wrapping_add(c);
        out[3] = out[3].wrapping_add(d);
        out[4] = out[4].wrapping_add(e);
        out[5] = out[5].wrapping_add(f);
        out[6] = out[6].wrapping_add(g);
        out[7] = out[7].wrapping_add(h);

    }

}

fn ch256(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (!x & z);
}

fn maj256(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn lsigma256_0(x: u32) -> u32 {
    return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
}

fn lsigma256_1(x: u32) -> u32 {
    return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
}

fn ssigma256_0(x: u32) -> u32 {
    return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
}

fn ssigma256_1(x: u32) -> u32 {
    return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
}

fn ch512(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ (!x & z);
}

fn maj512(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn lsigma512_0(x: u64) -> u64 {
    return ((x >> 28) | (x << 36)) ^ ((x >> 34) | (x << 30)) ^ ((x >> 39) | (x << 25));
}

fn lsigma512_1(x: u64) -> u64 {
    return ((x >> 14) | (x << 50)) ^ ((x >> 18) | (x << 46)) ^ ((x >> 41) | (x << 23));
}

fn ssigma512_0(x: u64) -> u64 {
    return ((x >> 1) | (x << 63)) ^ ((x >> 8) | (x << 56)) ^ (x >> 7);
}

fn ssigma512_1(x: u64) -> u64 {
    return ((x >> 19) | (x << 45)) ^ ((x >> 61) | (x << 3)) ^ (x >> 6);
}
