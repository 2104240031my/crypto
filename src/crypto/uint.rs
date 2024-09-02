use crate::crypto::CryptoError;

pub struct Uint256 {
    pub w: [u32; 8]
}

pub struct Uint512 {
    pub w: [u32; 16]
}

impl Uint256 {

    pub fn new() -> Uint256 {
        return Uint256{ w: [0; 8] };
    }

    pub fn new_as(u: usize) -> Uint256 {
        return Uint256{ w: [0, 0, 0, 0, 0, 0, (u >> 32) as u32, (u & 0xffffffffusize) as u32]};
    }

    pub fn add(v: &mut Uint256, lhs: &Uint256, rhs: &Uint256) {
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + (lhs.w[i] as u64) + (rhs.w[i] as u64);
            v.w[i] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
        }
    }

    pub fn add_assign(&mut self, rhs: &Uint256) -> &Uint256 {

        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (self.w[u] as u64) + (rhs.w[u] as u64);
            self.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }

        return self;

    }

    pub fn mul(into: &mut Uint256, lhs: &Uint256, rhs: &Uint256) {

        for i in 0..8 {
            for j in 0..8 {

                let tmp: u64 = (lhs.w[i] as u64) * (rhs.w[j] as u64);
                let mut acc: u64;
                let mut k: usize;

                acc = tmp & 0xffffffffu64;
                k = i + j + 1;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }

                acc = tmp >> 32;
                k = i + j;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }

            }
        }

    }

    pub fn mul_to_uint512(into: &mut Uint521, lhs: &Uint256, rhs: &Uint256) {

        for i in 0..8 {
            for j in 0..8 {

                let tmp: u64 = (lhs.w[i] as u64) * (rhs.w[j] as u64);
                let mut acc: u64;
                let mut k: usize;

                acc = tmp & 0xffffffffu64;
                k = i + j + 1;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }

                acc = tmp >> 32;
                k = i + j;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }

            }
        }

    }

    pub fn eq(lhs: &Uint256, rhs: &Uint256) -> bool {

        let mut acc: u64 = 0;

        for i in 0..8 {
            acc = acc | ((lhs.w[i] as u64) ^ (rhs.w[i] as u64));
        }

        return acc == 0;

    }

    pub fn lt(lhs: &Uint256, rhs: &Uint256) -> bool {

        let mut bit: u64 = 1; // current bit
        let mut l: u64   = 0; // summary of left
        let mut r: u64   = 0; // summary of right

        for i in (0..8).rev() {
            let gt_mask: u64 = if lhs.w[i] > rhs.w[i] { u64::MAX } else { 0u64 };
            let lt_mask: u64 = if lhs.w[i] < rhs.w[i] { u64::MAX } else { 0u64 };
            l = l ^ (bit & gt_mask);
            r = r ^ (bit & lt_mask);
            bit = bit << 1;
        }

        return l < r;

    }

}
