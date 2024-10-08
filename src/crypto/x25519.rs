use crate::crypto::ec25519::Ec25519Uint;
use crate::crypto::ec25519::A24;
use crate::crypto::ec25519::U;

pub struct X25519 {}

pub const X25519_PRIVATE_KEY_LEN: usize   = 32;
pub const X25519_PUBLIC_KEY_LEN: usize    = 32;
pub const X25519_SHARED_SECRET_LEN: usize = 32;

fn x25519(v: &mut Ec25519Uint, k: &Ec25519Uint, u: &Ec25519Uint) {

    let x1: Ec25519Uint     = u.clone();
    let mut x2: Ec25519Uint = Ec25519Uint::from_usize(1);
    let mut z2: Ec25519Uint = Ec25519Uint::from_usize(0);
    let mut x3: Ec25519Uint = u.clone();
    let mut z3: Ec25519Uint = Ec25519Uint::from_usize(1);

    let mut t0: Ec25519Uint = Ec25519Uint::new();
    let mut t1: Ec25519Uint = Ec25519Uint::new();
    let mut t2: Ec25519Uint = Ec25519Uint::new();
    let mut t3: Ec25519Uint = Ec25519Uint::new();
    let mut t4: Ec25519Uint = Ec25519Uint::new();

    let mut swap: usize = 0;
    let mut bit: usize;

    let mut j: usize = 31; // i == 0 ? j = 31 : 32;

    for i in 0..8 {

        while j > 0 {

            j = j - 1;

            bit = ((k.buf.w[i] as usize) >> j) & 1;
            swap = swap ^ bit;
            Ec25519Uint::constant_time_swap(&mut x2, &mut x3, swap == 1);
            Ec25519Uint::constant_time_swap(&mut z2, &mut z3, swap == 1);
            swap = bit;

            Ec25519Uint::gadd(&mut t0, &x2, &z2);   // A  = x2 + z2
            Ec25519Uint::gsub(&mut t1, &x2, &z2);   // B  = x2 - z2
            Ec25519Uint::gsqr(&mut t2, &t0);        // AA = A ^ 2
            Ec25519Uint::gsqr(&mut t3, &t1);        // BB = B ^ 2
            Ec25519Uint::gmul(&mut x2, &t2, &t3);   // x2 = AA * BB
            Ec25519Uint::gsub(&mut t4, &t2, &t3);   // E  = AA - BB
            Ec25519Uint::gmul(&mut t3, &A24, &t4);
            Ec25519Uint::gadd_assign(&mut t3, &t2);
            Ec25519Uint::gmul(&mut z2, &t4, &t3);   // z2 = E * (AA + a24 * E)
            Ec25519Uint::gsub(&mut t2, &x3, &z3);   // D  = x3 - z3
            Ec25519Uint::gmul_assign(&mut t2, &t0); // DA = D * A
            Ec25519Uint::gadd(&mut t3, &x3, &z3);   // C  = x3 + z3
            Ec25519Uint::gmul_assign(&mut t3, &t1); // CB = C * B
            Ec25519Uint::gadd(&mut t0, &t2, &t3);
            Ec25519Uint::gmul(&mut x3, &t0, &t0);   // x3 = (DA + CB) ^ 2
            Ec25519Uint::gsub(&mut t0, &t2, &t3);
            Ec25519Uint::gsqr_assign(&mut t0);
            Ec25519Uint::gmul(&mut z3, &x1, &t0);   // z3 = x1 * (DA - CB) ^ 2

        }

        j = 32;

    }

    Ec25519Uint::constant_time_swap(&mut x2, &mut x3, swap == 1);
    Ec25519Uint::constant_time_swap(&mut z2, &mut z3, swap == 1);

    Ec25519Uint::gdiv(v, &x2, &z2); // return x2 * (z2 ** (p - 2))

}

impl Dh for X25519 {

    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519_PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough"));
        } else if pub_key.len() < X25519_PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough"));
        }

        let k: Ec25519Uint = Ec25519Uint::try_from_bytes_as_scalar(priv_key).ok()?;
        let mut v: Ec25519Uint = Ec25519Uint::new();
        x25519(&mut v, &k, &U);
        v.try_into_bytes(pub_key)?;

        return None;

    }

    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519_PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough"));
        } else if peer_pub_key.len() < X25519_PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough"));
        } else if shared_secret.len() < X25519_SHARED_SECRET_LEN {
            return Some(CryptoError::new("the length of \"shared_secret\" is not enough"));
        }

        let k: Ec25519Uint = Ec25519Uint::try_from_bytes_as_scalar(priv_key).ok()?;
        let u: Ec25519Uint = Ec25519Uint::try_from_bytes_as_u_coordinate(peer_pub_key).ok()?;
        let mut v: Ec25519Uint = Ec25519Uint::new();
        x25519(&mut v, &k, &u);
        v.try_into_bytes(shared_secret)?;

        return None;

    }

}
