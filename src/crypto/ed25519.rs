
// [*1] https://www.rfc-editor.org/rfc/rfc8032.html section-5.1, section-5.1.6, section-2
// [*2] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3002-2020.pdf
// [*3] https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf
// [*4] https://github.com/golang/go/blob/master/src/crypto/ed25519/ed25519.go
// [*5] https://cr.yp.to/bib/2003/joye-ladder.pdf
// [*6] https://dspace.jaist.ac.jp/dspace/bitstream/10119/9146/7/paper.pdf

// - 拡張射影座標系について [*3] pp17

pub struct Ed25519 {}


const ED25519_PRIVATE_KEY_LEN: usize  = 32;
const ED25519_PUBLIC_KEY_LEN: usize   = 32;
const ED25519_SIGNATURE_LEN: usize    = 64;


impl Ed25519 {

    // PureEdDSA
    pub fn sign(priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Option<CryptoError> {

        // ENCI: encode int
        // DECI: decode int
        // ENCE: encode point
        // ENC

        // h = SHA-512(k)
        let mut h: [u8; 64] = [0; 64];
        Sha512::digest_oneshot(&priv_key, &mut h);

        // h[0]{0} = 0, h[0]{1} = 0, h[0]{2} = 0, h[31]{7} = 0, h[32]{6} = 1
        // s = DECI(s[0..32])
        let s: Curve25519Uint = Curve25519Uint::try_new_from_bytes_as_scalar(&h[..32]).ok()?;

        // A = ENCE([s]B)
        let mut a: Curve25519Point = Curve25519Point::new();
        Curve25519Point::scalar_mul(&mut a, &s);

        // r = DECI(SHA-512(h[32..64] || M)) mod L
        let r: Curve25519Uint = {

            let mut sha512 = Sha512::new();
            let mut r: [u8; 64] = [0; 64];
            sha512.update(&h[32..]);
            sha512.update(&msg);
            sha512.digest(&mut r[..]);

            // DECI(SHA-512(h[32..64] || M)) mod L
            // cf. https://www.cryptrec.go.jp/exreport/cryptrec-ex-3102-2021.pdf, pp. 9
            let mut buf: Uint512 = Uint512{ w: [
                u32::from_le_bytes(r[60..64].try_into().unwrap()),
                u32::from_le_bytes(r[56..60].try_into().unwrap()),
                u32::from_le_bytes(r[52..56].try_into().unwrap()),
                u32::from_le_bytes(r[48..52].try_into().unwrap()),
                u32::from_le_bytes(r[44..48].try_into().unwrap()),
                u32::from_le_bytes(r[40..44].try_into().unwrap()),
                u32::from_le_bytes(r[36..40].try_into().unwrap()),
                u32::from_le_bytes(r[32..36].try_into().unwrap()),
                u32::from_le_bytes(r[28..32].try_into().unwrap()),
                u32::from_le_bytes(r[24..28].try_into().unwrap()),
                u32::from_le_bytes(r[20..24].try_into().unwrap()),
                u32::from_le_bytes(r[16..20].try_into().unwrap()),
                u32::from_le_bytes(r[12..16].try_into().unwrap()),
                u32::from_le_bytes(r[ 8..12].try_into().unwrap()),
                u32::from_le_bytes(r[ 4.. 8].try_into().unwrap()),
                u32::from_le_bytes(r[ 0.. 4].try_into().unwrap())
            ]};



            v

            // x = a + b * 2^168 + c * 2^336 mod L
            // cf. https://github.com/golang/go/blob/master/src/crypto/internal/edwards25519/scalar.go

        };

        // R = ENCE([r]B)

        // k = DECI(SHA-512(R || A || M)) mod L

        // S = (r + k * s) mod L
        //   = ((k * s) mod L) + r mod L
        // # k * s の結果をuint512として持ってきて、それをLに収める、そうすればmul_mod_lを実装せずによくなる（ほかのmod L処理も全部Uint512 mod Lの処理やから）
        // # つまり Uint512 mod Lの処理だけ必要

        // signature = R || ENCO(S)    <- ENCO? typo?

        return None;

    }

    fn add_mod_l() {

    }

    fn mul_mod_l() {

        // 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        // - use Uint256 as buffer
        // - handle the overflow part (0 ~ 27742317777372353535851937790883648493)
        // # 512-bit int as (c (2-bit) * (Uint255 ** 2)) + (b (255-bit) * Uint255) + (a (255-bit))


    }

    fn reduce_to_lt_l(v: &mut Curve25519Uint) {
        let mask: u32 = if Uint256::lt(&v, &L) { 0u32 } else { u32::MAX };
        let mut acc: u64 = 0;
        for i in (0..8).rev() {
            acc = acc + (v.w[i] as u64) + ((L_ADDINV256.w[i] & mask) as u64);
            v.w[i] = (acc & 0xffffffff) as u32;
            acc = acc >> 32;
        }
    }

    unsafe fn add_raw(v: *mut Self, lhs: *const Self, rhs: *const Self) {
        Uint256::add(&mut (*v).buf, &(*lhs).buf, &(*rhs).buf);
        Self::reduce_to_lt_l(&mut (*v));
    }

    unsafe fn mod_raw(v: *mut Self, lhs: *const Self, rhs: *const Self) {

    }

}