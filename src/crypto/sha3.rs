use crate::crypto::CryptoError;

pub struct Sha3_256 {
    s: Sha3StateArray, // Keccak1600 state
    // d: usize,         // message digest size (in bytes)
    // r: usize,         // rate (in bytes)
    // w: usize,         // lane size of Keccak-p permutation (in bytes), i.e., r / 8
}

struct Sha3StateArray {
    a: [[u64; 5]; 5] // Keccak1600 state
}

static RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

static ROT: [[usize; 5]; 5] = [
    [ 0, 36,  3, 41, 18], //  0,  1, 62, 28, 27,
    [ 1, 44, 10, 45 , 2], // 36, 44,  6, 55, 20,
    [62,  6, 43, 15, 61], //  3, 10, 43, 25, 39,
    [28, 55, 25, 21, 56], // 41, 45, 15, 21,  8,
    [27, 20, 39,  8, 14]  // 18,  2, 61, 56, 14
];

fn rotl64(u: u64, r: usize) -> u64 {
    return (u << r) | (u >> (64 - r));
}

fn absorb(s: &mut Sha3StateArray) {

    for i in 0..24 {

        let mut b: [[u64; 5]; 5] = [[0u64; 5]; 5];

        b[0] = s.a[0][0] ^ s.a[0][1] ^ s.a[0][2] ^ s.a[0][3] ^ s.a[0][4];
        b[1] = s.a[1][0] ^ s.a[1][1] ^ s.a[1][2] ^ s.a[1][3] ^ s.a[1][4];
        b[2] = s.a[2][0] ^ s.a[2][1] ^ s.a[2][2] ^ s.a[2][3] ^ s.a[2][4];
        b[3] = s.a[3][0] ^ s.a[3][1] ^ s.a[3][2] ^ s.a[3][3] ^ s.a[3][4];
        b[4] = s.a[4][0] ^ s.a[4][1] ^ s.a[4][2] ^ s.a[4][3] ^ s.a[4][4];

        b[5] = b[4] ^ rotl64(b[1], 1);
        b[6] = b[0] ^ rotl64(b[2], 1);
        b[7] = b[1] ^ rotl64(b[3], 1);
        b[8] = b[2] ^ rotl64(b[4], 1);
        b[9] = b[3] ^ rotl64(b[0], 1);

        for y in 0..5 {
            s.a[0][y] = s.a[0][y] ^ b[5];
            s.a[1][y] = s.a[1][y] ^ b[6];
            s.a[2][y] = s.a[2][y] ^ b[7];
            s.a[3][y] = s.a[3][y] ^ b[8];
            s.a[4][y] = s.a[4][y] ^ b[9];
        }

        for x in 0..5 {
            b[0][(2 * x +  0) % 5] = rotl64(s.a[x][0], ROT[x][0]);
            b[1][(2 * x +  3) % 5] = rotl64(s.a[x][1], ROT[x][1]);
            b[2][(2 * x +  6) % 5] = rotl64(s.a[x][2], ROT[x][2]);
            b[3][(2 * x +  9) % 5] = rotl64(s.a[x][3], ROT[x][3]);
            b[4][(2 * x + 12) % 5] = rotl64(s.a[x][4], ROT[x][4]);
        }

        for x in 0..5 {
            s.a[x][0] = b[x][0] ^ ((!b[(x + 1) % 5][0]) & b[(x + 2) % 5][0]);
            s.a[x][1] = b[x][1] ^ ((!b[(x + 1) % 5][1]) & b[(x + 2) % 5][1]);
            s.a[x][2] = b[x][2] ^ ((!b[(x + 1) % 5][2]) & b[(x + 2) % 5][2]);
            s.a[x][3] = b[x][3] ^ ((!b[(x + 1) % 5][3]) & b[(x + 2) % 5][3]);
            s.a[x][4] = b[x][4] ^ ((!b[(x + 1) % 5][4]) & b[(x + 2) % 5][4]);
        }

        s.a[0][0] = s.a[0][0] ^ RC[i];

    }

}

fn reset(s: &mut Sha3StateArray) {
    for y in 0..5 {
        for x in 0..5 {
            s.a[x][y] = 0;
        }
    }
}

impl Sha3_256 {

    pub fn compute(msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        let mut s: Sha3StateArray = Sha3StateArray{ a: [[0; 5]; 5] };
        let mut ofs: usize = 0;
        let mut block: [u64; 25] = [0u64; 25];

        while msg.len() - ofs >= sha3.r {
            for i in 0..sha3.w {
                block[i] = (
                    ((msg[ofs + 0] as u64) <<  0) | ((msg[ofs + 1] as u64) <<  8) |
                    ((msg[ofs + 2] as u64) << 16) | ((msg[ofs + 3] as u64) << 24) |
                    ((msg[ofs + 4] as u64) << 31) | ((msg[ofs + 5] as u64) << 40) |
                    ((msg[ofs + 6] as u64) << 48) | ((msg[ofs + 7] as u64) << 56)
                );
                ofs = ofs + 8;
            }
            for y in 0..5 {
                for x in 0..5 {
                    s.a[x][y] = s.a[x][y] ^ block[x + 5 * y];
                }
            }
            absorb(&mut s);
        }

        let mut x: usize = 0;
        let mut y: usize = 0;
        let mut n: usize = 0;

        while ofs < msg.len() {
            s.a[x][y] = s.a[x][y] ^ ((msg[ofs] as u64) << n);
            n = n + 8;
            if n == 64 {
                n = 0;
                x = x + 1;
                if x == 5 {
                    y = y + 1;
                }
            }
            ofs = ofs + 1;
        }

        s.a[x][y] = s.a[x][y] ^ (0x06u64 << n);
        x = (s.w % 5) - 1;
        y = s.w / 5;
        s.a[x][y] = s.a[x][y] ^ (0x80u64 << 56);
        absorb(&mut s);

        n = 0;
        x = 0;
        y = 0;

        for i in 0..s.d {
            md[i] = ((s.a[x][y] >> n) & 0xff) as u8;
            n = n + 8;
            if n == 64 {
                n = 0;
                x = x + 1;
                if x == 5 {
                    x = 0;
                    y = y + 1;
                }
            }
        }

        return None;

    }

}