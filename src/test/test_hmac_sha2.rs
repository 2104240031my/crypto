use crate::crypto::Mac;
use crate::crypto::hmac_sha2::HmacSha224;
use crate::crypto::hmac_sha2::HmacSha256;
use crate::crypto::hmac_sha2::HmacSha384;
use crate::crypto::hmac_sha2::HmacSha512;
use crate::test::{
    printbytesln,
    eqbytes
};

static K: [u8; 200] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7
];

fn test_hmac_sha224_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 28] = [0; 28];

    HmacSha224::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha224::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..28]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha256_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 32] = [0; 32];

    HmacSha256::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha256::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..32]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha384_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 48] = [0; 48];

    HmacSha384::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha384::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..48]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha512_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 64] = [0; 64];

    HmacSha512::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha512::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..64]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha224() {

    let d1: [u8; 28] = [
        0xC7, 0x40, 0x5E, 0x3A, 0xE0, 0x58, 0xE8, 0xCD, 0x30, 0xB0, 0x8B, 0x41, 0x40, 0x24, 0x85, 0x81,
        0xED, 0x17, 0x4C, 0xB3, 0x4E, 0x12, 0x24, 0xBC, 0xC1, 0xEF, 0xC8, 0x1B
    ];
    test_hmac_sha224_inner(&K[..64], "Sample message for keylen=blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 28] = [
        0xE3, 0xD2, 0x49, 0xA8, 0xCF, 0xB6, 0x7E, 0xF8, 0xB7, 0xA1, 0x69, 0xE9, 0xA0, 0xA5, 0x99, 0x71,
        0x4A, 0x2C, 0xEC, 0xBA, 0x65, 0x99, 0x9A, 0x51, 0xBE, 0xB8, 0xFB, 0xBE
    ];
    test_hmac_sha224_inner(&K[..28], "Sample message for keylen<blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 28] = [
        0x91, 0xC5, 0x25, 0x09, 0xE5, 0xAF, 0x85, 0x31, 0x60, 0x1A, 0xE6, 0x23, 0x00, 0x99, 0xD9, 0x0B,
        0xEF, 0x88, 0xAA, 0xEF, 0xB9, 0x61, 0xF4, 0x08, 0x0A, 0xBC, 0x01, 0x4D
    ];
    test_hmac_sha224_inner(&K[..100], "Sample message for keylen=blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha256() {

    let d1: [u8; 32] = [
        0x8B, 0xB9, 0xA1, 0xDB, 0x98, 0x06, 0xF2, 0x0D, 0xF7, 0xF7, 0x7B, 0x82, 0x13, 0x8C, 0x79, 0x14,
        0xD1, 0x74, 0xD5, 0x9E, 0x13, 0xDC, 0x4D, 0x01, 0x69, 0xC9, 0x05, 0x7B, 0x13, 0x3E, 0x1D, 0x62
    ];
    test_hmac_sha256_inner(&K[..64], "Sample message for keylen=blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 32] = [
        0xA2, 0x8C, 0xF4, 0x31, 0x30, 0xEE, 0x69, 0x6A, 0x98, 0xF1, 0x4A, 0x37, 0x67, 0x8B, 0x56, 0xBC,
        0xFC, 0xBD, 0xD9, 0xE5, 0xCF, 0x69, 0x71, 0x7F, 0xEC, 0xF5, 0x48, 0x0F, 0x0E, 0xBD, 0xF7, 0x90
    ];
    test_hmac_sha256_inner(&K[..32], "Sample message for keylen<blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 32] = [
        0xBD, 0xCC, 0xB6, 0xC7, 0x2D, 0xDE, 0xAD, 0xB5, 0x00, 0xAE, 0x76, 0x83, 0x86, 0xCB, 0x38, 0xCC,
        0x41, 0xC6, 0x3D, 0xBB, 0x08, 0x78, 0xDD, 0xB9, 0xC7, 0xA3, 0x8A, 0x43, 0x1B, 0x78, 0x37, 0x8D
    ];
    test_hmac_sha256_inner(&K[..100], "Sample message for keylen=blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha384() {

    let d1: [u8; 48] = [
        0x63, 0xC5, 0xDA, 0xA5, 0xE6, 0x51, 0x84, 0x7C, 0xA8, 0x97, 0xC9, 0x58, 0x14, 0xAB, 0x83, 0x0B,
        0xED, 0xED, 0xC7, 0xD2, 0x5E, 0x83, 0xEE, 0xF9, 0x19, 0x5C, 0xD4, 0x58, 0x57, 0xA3, 0x7F, 0x44,
        0x89, 0x47, 0x85, 0x8F, 0x5A, 0xF5, 0x0C, 0xC2, 0xB1, 0xB7, 0x30, 0xDD, 0xF2, 0x96, 0x71, 0xA9
    ];
    test_hmac_sha384_inner(&K[..128], "Sample message for keylen=blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 48] = [
        0x6E, 0xB2, 0x42, 0xBD, 0xBB, 0x58, 0x2C, 0xA1, 0x7B, 0xEB, 0xFA, 0x48, 0x1B, 0x1E, 0x23, 0x21,
        0x14, 0x64, 0xD2, 0xB7, 0xF8, 0xC2, 0x0B, 0x9F, 0xF2, 0x20, 0x16, 0x37, 0xB9, 0x36, 0x46, 0xAF,
        0x5A, 0xE9, 0xAC, 0x31, 0x6E, 0x98, 0xDB, 0x45, 0xD9, 0xCA, 0xE7, 0x73, 0x67, 0x5E, 0xEE, 0xD0
    ];
    test_hmac_sha384_inner(&K[..48], "Sample message for keylen<blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 48] = [
        0x5B, 0x66, 0x44, 0x36, 0xDF, 0x69, 0xB0, 0xCA, 0x22, 0x55, 0x12, 0x31, 0xA3, 0xF0, 0xA3, 0xD5,
        0xB4, 0xF9, 0x79, 0x91, 0x71, 0x3C, 0xFA, 0x84, 0xBF, 0xF4, 0xD0, 0x79, 0x2E, 0xFF, 0x96, 0xC2,
        0x7D, 0xCC, 0xBB, 0xB6, 0xF7, 0x9B, 0x65, 0xD5, 0x48, 0xB4, 0x0E, 0x85, 0x64, 0xCE, 0xF5, 0x94
    ];
    test_hmac_sha384_inner(&K[..], "Sample message for keylen=blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha512() {

    let d1: [u8; 64] = [
        0xFC, 0x25, 0xE2, 0x40, 0x65, 0x8C, 0xA7, 0x85, 0xB7, 0xA8, 0x11, 0xA8, 0xD3, 0xF7, 0xB4, 0xCA,
        0x48, 0xCF, 0xA2, 0x6A, 0x8A, 0x36, 0x6B, 0xF2, 0xCD, 0x1F, 0x83, 0x6B, 0x05, 0xFC, 0xB0, 0x24,
        0xBD, 0x36, 0x85, 0x30, 0x81, 0x81, 0x1D, 0x6C, 0xEA, 0x42, 0x16, 0xEB, 0xAD, 0x79, 0xDA, 0x1C,
        0xFC, 0xB9, 0x5E, 0xA4, 0x58, 0x6B, 0x8A, 0x0C, 0xE3, 0x56, 0x59, 0x6A, 0x55, 0xFB, 0x13, 0x47
    ];
    test_hmac_sha512_inner(&K[..128], "Sample message for keylen=blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 64] = [
        0xFD, 0x44, 0xC1, 0x8B, 0xDA, 0x0B, 0xB0, 0xA6, 0xCE, 0x0E, 0x82, 0xB0, 0x31, 0xBF, 0x28, 0x18,
        0xF6, 0x53, 0x9B, 0xD5, 0x6E, 0xC0, 0x0B, 0xDC, 0x10, 0xA8, 0xA2, 0xD7, 0x30, 0xB3, 0x63, 0x4D,
        0xE2, 0x54, 0x5D, 0x63, 0x9B, 0x0F, 0x2C, 0xF7, 0x10, 0xD0, 0x69, 0x2C, 0x72, 0xA1, 0x89, 0x6F,
        0x1F, 0x21, 0x1C, 0x2B, 0x92, 0x2D, 0x1A, 0x96, 0xC3, 0x92, 0xE0, 0x7E, 0x7E, 0xA9, 0xFE, 0xDC
    ];
    test_hmac_sha512_inner(&K[..64], "Sample message for keylen<blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 64] = [
        0xD9, 0x3E, 0xC8, 0xD2, 0xDE, 0x1A, 0xD2, 0xA9, 0x95, 0x7C, 0xB9, 0xB8, 0x3F, 0x14, 0xE7, 0x6A,
        0xD6, 0xB5, 0xE0, 0xCC, 0xE2, 0x85, 0x07, 0x9A, 0x12, 0x7D, 0x3B, 0x14, 0xBC, 0xCB, 0x7A, 0xA7,
        0x28, 0x6D, 0x4A, 0xC0, 0xD4, 0xCE, 0x64, 0x21, 0x5F, 0x2B, 0xC9, 0xE6, 0x87, 0x0B, 0x33, 0xD9,
        0x74, 0x38, 0xBE, 0x4A, 0xAA, 0x20, 0xCD, 0xA5, 0xC5, 0xA9, 0x12, 0xB4, 0x8B, 0x8E, 0x27, 0xF3
    ];
    test_hmac_sha512_inner(&K[..], "Sample message for keylen=blocklen".as_bytes(), &d3[..]);

}

pub fn test_hmac_sha2() {
    test_hmac_sha224();
    test_hmac_sha256();
    test_hmac_sha384();
    test_hmac_sha512();
}