use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::DiffieHellman;
use crate::crypto::curve_over_fp25519::Fp25519Uint;
use crate::crypto::curve_over_fp25519::A24;
use crate::crypto::curve_over_fp25519::U;

pub struct X25519 {}

impl DiffieHellman for X25519 {

    const PRIVATE_KEY_LEN: usize   = X25519_PRIVATE_KEY_LEN;
    const PUBLIC_KEY_LEN: usize    = X25519_PUBLIC_KEY_LEN;
    const SHARED_SECRET_LEN: usize = X25519_SHARED_SECRET_LEN;

    fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() != X25519_PRIVATE_KEY_LEN || pub_key.len() != X25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let k: Fp25519Uint = Fp25519Uint::try_from_bytes_as_scalar(priv_key)?;
        let mut v: Fp25519Uint = Fp25519Uint::new();
        x25519(&k, &U, &mut v);
        v.try_into_bytes(pub_key)?;

        return Ok(());

    }

    fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError> {

        if priv_key.len() != X25519_PRIVATE_KEY_LEN || peer_pub_key.len() != X25519_PUBLIC_KEY_LEN ||
            shared_secret.len() != X25519_SHARED_SECRET_LEN {
            return Err(CryptoError::new(CryptoErrorCode::BufferLengthIncorrect));
        }

        let k: Fp25519Uint = Fp25519Uint::try_from_bytes_as_scalar(priv_key)?;
        let u: Fp25519Uint = Fp25519Uint::try_from_bytes_as_u_coordinate(peer_pub_key)?;
        let mut v: Fp25519Uint = Fp25519Uint::new();
        x25519(&k, &u, &mut v);
        v.try_into_bytes(shared_secret)?;

        return Ok(());

    }

}

const X25519_PRIVATE_KEY_LEN: usize   = 32;
const X25519_PUBLIC_KEY_LEN: usize    = 32;
const X25519_SHARED_SECRET_LEN: usize = 32;

fn x25519(k: &Fp25519Uint, u: &Fp25519Uint, v: &mut Fp25519Uint) {

    let mut x2: Fp25519Uint = Fp25519Uint::from_usize(1);
    let mut z2: Fp25519Uint = Fp25519Uint::from_usize(0);
    let mut x3: Fp25519Uint = u.clone();
    let mut z3: Fp25519Uint = Fp25519Uint::from_usize(1);
    let mut t1: Fp25519Uint = Fp25519Uint::new();
    let mut t2: Fp25519Uint = Fp25519Uint::new();
    let mut t3: Fp25519Uint = Fp25519Uint::new();
    let mut t4: Fp25519Uint = Fp25519Uint::new();
    let mut t5: Fp25519Uint = Fp25519Uint::new();

    let mut swap: bool = false;
    let mut j: usize   = 31; // i == 0 ? j = 31 : 32;

    for i in 0..8 {

        while j > 0 {

            j = j - 1;

            let bit: bool = ((k.words[i] as usize) >> j) & 1 == 1;
            swap = swap ^ bit;
            Fp25519Uint::constant_time_swap(&mut x2, &mut x3, swap);
            Fp25519Uint::constant_time_swap(&mut z2, &mut z3, swap);
            swap = bit;

            Fp25519Uint::gadd(&mut t1, &x2, &z2);   // A  = x2 + z2
            Fp25519Uint::gsub(&mut t2, &x2, &z2);   // B  = x2 - z2
            Fp25519Uint::gsqr(&mut t3, &t1);        // AA = A ** 2
            Fp25519Uint::gsqr(&mut t4, &t2);        // BB = B ** 2
            Fp25519Uint::gmul(&mut x2, &t3, &t4);   // x2 = AA * BB
            Fp25519Uint::gsub(&mut t5, &t3, &t4);   // E  = AA - BB
            Fp25519Uint::gmul(&mut t4, &A24, &t5);
            Fp25519Uint::gadd_assign(&mut t4, &t3);
            Fp25519Uint::gmul(&mut z2, &t5, &t4);   // z2 = E * (AA + a24 * E)
            Fp25519Uint::gsub(&mut t3, &x3, &z3);   // D  = x3 - z3
            Fp25519Uint::gmul_assign(&mut t3, &t1); // DA = D * A
            Fp25519Uint::gadd(&mut t4, &x3, &z3);   // C  = x3 + z3
            Fp25519Uint::gmul_assign(&mut t4, &t2); // CB = C * B
            Fp25519Uint::gadd(&mut t1, &t3, &t4);
            Fp25519Uint::gsqr(&mut x3, &t1);        // x3 = (DA + CB) ** 2
            Fp25519Uint::gsub(&mut t1, &t3, &t4);
            Fp25519Uint::gsqr_assign(&mut t1);
            Fp25519Uint::gmul(&mut z3, u, &t1);     // z3 = x1 * ((DA - CB) ** 2)

        }

        j = 32;

    }

    Fp25519Uint::constant_time_swap(&mut x2, &mut x3, swap);
    Fp25519Uint::constant_time_swap(&mut z2, &mut z3, swap);
    Fp25519Uint::gdiv(v, &x2, &z2); // return x2 * (z2 ** (p - 2))

}