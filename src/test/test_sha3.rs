use crate::crypto::Hash;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;
use crate::test::{
    printbytesln,
    eqbytes
};

static M0: [u8; 200] = [0xa3; 200];

fn test_sha3_224_inner(m: &[u8], d: &[u8]) {

    let mut out: [u8; 28] = [0; 28];

    Sha3224::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut sha3 = Sha3224::new();
    sha3.reset().unwrap();
    for i in 0..m.len() {
        sha3.update(&m[i..(i + 1)]).unwrap();
    }
    sha3.digest(&mut out[..28]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_sha3_256_inner(m: &[u8], d: &[u8]) {

    let mut out: [u8; 32] = [0; 32];

    Sha3256::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut sha3 = Sha3256::new();
    sha3.reset().unwrap();
    for i in 0..m.len() {
        sha3.update(&m[i..(i + 1)]).unwrap();
    }
    sha3.digest(&mut out[..32]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_sha3_384_inner(m: &[u8], d: &[u8]) {

    let mut out: [u8; 48] = [0; 48];

    Sha3384::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut sha3 = Sha3384::new();
    sha3.reset().unwrap();
    for i in 0..m.len() {
        sha3.update(&m[i..(i + 1)]).unwrap();
    }
    sha3.digest(&mut out[..48]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_sha3_512_inner(m: &[u8], d: &[u8]) {

    let mut out: [u8; 64] = [0; 64];

    Sha3512::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut sha3 = Sha3512::new();
    sha3.reset().unwrap();
    for i in 0..m.len() {
        sha3.update(&m[i..(i + 1)]).unwrap();
    }
    sha3.digest(&mut out[..64]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing SHA3-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_sha3_224() {
    let d1: [u8; 28] = [
        0x93, 0x76, 0x81, 0x6A, 0xBA, 0x50, 0x3F, 0x72, 0xF9, 0x6C, 0xE7, 0xEB, 0x65, 0xAC, 0x09, 0x5D,
        0xEE, 0xE3, 0xBE, 0x4B, 0xF9, 0xBB, 0xC2, 0xA1, 0xCB, 0x7E, 0x11, 0xE0
    ];
    test_sha3_224_inner(&M0[..], &d1[..]);
}

fn test_sha3_256() {
    let d1: [u8; 32] = [
        0x79, 0xF3, 0x8A, 0xDE, 0xC5, 0xC2, 0x03, 0x07, 0xA9, 0x8E, 0xF7, 0x6E, 0x83, 0x24, 0xAF, 0xBF,
        0xD4, 0x6C, 0xFD, 0x81, 0xB2, 0x2E, 0x39, 0x73, 0xC6, 0x5F, 0xA1, 0xBD, 0x9D, 0xE3, 0x17, 0x87
    ];
    test_sha3_256_inner(&M0[..], &d1[..]);
}

fn test_sha3_384() {
    let d1: [u8; 48] = [
        0x18, 0x81, 0xDE, 0x2C, 0xA7, 0xE4, 0x1E, 0xF9, 0x5D, 0xC4, 0x73, 0x2B, 0x8F, 0x5F, 0x00, 0x2B,
        0x18, 0x9C, 0xC1, 0xE4, 0x2B, 0x74, 0x16, 0x8E, 0xD1, 0x73, 0x26, 0x49, 0xCE, 0x1D, 0xBC, 0xDD,
        0x76, 0x19, 0x7A, 0x31, 0xFD, 0x55, 0xEE, 0x98, 0x9F, 0x2D, 0x70, 0x50, 0xDD, 0x47, 0x3E, 0x8F
    ];
    test_sha3_384_inner(&M0[..], &d1[..]);
}

fn test_sha3_512() {
    let d1: [u8; 64] = [
        0xE7, 0x6D, 0xFA, 0xD2, 0x20, 0x84, 0xA8, 0xB1, 0x46, 0x7F, 0xCF, 0x2F, 0xFA, 0x58, 0x36, 0x1B,
        0xEC, 0x76, 0x28, 0xED, 0xF5, 0xF3, 0xFD, 0xC0, 0xE4, 0x80, 0x5D, 0xC4, 0x8C, 0xAE, 0xEC, 0xA8,
        0x1B, 0x7C, 0x13, 0xC3, 0x0A, 0xDF, 0x52, 0xA3, 0x65, 0x95, 0x84, 0x73, 0x9A, 0x2D, 0xF4, 0x6B,
        0xE5, 0x89, 0xC5, 0x1C, 0xA1, 0xA4, 0xA8, 0x41, 0x6D, 0xF6, 0x54, 0x5A, 0x1C, 0xE8, 0xBA, 0x00
    ];
    test_sha3_512_inner(&M0[..], &d1[..]);
}

pub fn test_sha3() {
    test_sha3_224();
    test_sha3_256();
    test_sha3_384();
    test_sha3_512();
}