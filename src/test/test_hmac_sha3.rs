use crate::crypto::Mac;
use crate::crypto::hmac_sha3_3::HmacSha3256;
use crate::test::{
    printbytesln,
    eqbytes
};

use crate::crypto::Mac;
use crate::crypto::hmac_sha3_2::HmacSha224;
use crate::crypto::hmac_sha3_2::HmacSha256;
use crate::crypto::hmac_sha3_2::HmacSha384;
use crate::crypto::hmac_sha3_2::HmacSha512;
use crate::test::{
    printbytesln,
    eqbytes
};

static K: [u8; 172] = [
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
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB
];

fn test_hmac_sha3_224_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 28] = [0; 28];

    HmacSha3224::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha3224::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..28]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-224 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha3_256_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 32] = [0; 32];

    HmacSha3256::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha3256::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..32]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-256 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha3_384_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 48] = [0; 48];

    HmacSha3384::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha3384::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..48]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-384 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha3_512_inner(k: &[u8], m: &[u8], d: &[u8]) {

    let mut out: [u8; 64] = [0; 64];

    HmacSha3512::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

    let mut hmac = HmacSha3512::new(k).unwrap();
    hmac.reset().unwrap();
    for i in 0..m.len() {
        hmac.update(&m[i..(i + 1)]).unwrap();
    }
    hmac.compute(&mut out[..64]).unwrap();

    if !eqbytes(d, &out[..]) {
        println!("Err: testing HMAC-SHA3-512 is failed.");
        printbytesln(&d[..]);
        printbytesln(&out[..]);
    }

}

fn test_hmac_sha3_224() {

    let d1: [u8; 28] = [
        332cfd59 347fdb8e 576e7726 0be4aba2
        d6dc5311 7b3bfb52 c6d18c04
    ];
    test_hmac_sha3_224_inner(&K[..28], "Sample message for keylen<blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 28] = [
        d8b733bc f66c644a 12323d56 4e24dcf3
        fc75f231 f3b67968 359100c7
    ];
    test_hmac_sha3_224_inner(&K[..144], "Sample message for keylen=blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 28] = [
        078695ee cc227c63 6ad31d06 3a15dd05
        a7e819a6 6ec6d8de 1e193e59
    ];
    test_hmac_sha3_224_inner(&K[..172], "Sample message for keylen>blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha3_256() {

    let d1: [u8; 32] = [
        4fe8e202 c4f058e8 dddc23d8 c34e4673
        43e23555 e24fc2f0 25d598f5 58f67205
    ];
    test_hmac_sha3_256_inner(&K[..32], "Sample message for keylen<blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 32] = [
        68b94e2e 538a9be4 103bebb5 aa016d47
        961d4d1a a9060613 13b557f8 af2c3faa
    ];
    test_hmac_sha3_256_inner(&K[..136], "Sample message for keylen=blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 32] = [
        9bcf2c23 8e235c3c e88404e8 13bd2f3a
        97185ac6 f238c63d 6229a00b 07974258
    ];
    test_hmac_sha3_256_inner(&K[..168], "Sample message for keylen>blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha3_384() {

    let d1: [u8; 48] = [
        d588a3c5 1f3f2d90 6e8298c1 199aa8ff
        62962181 27f6b38a 90b6afe2 c5617725
        bc99987f 79b22a55 7b6520db 710b7f42
    ];
    test_hmac_sha3_384_inner(&K[..48], "Sample message for keylen<blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 48] = [
        a27d24b5 92e8c8cb f6d4ce6f c5bf62d8
        fc98bf2d 486640d9 eb8099e2 4047837f
        5f3bffbe 92dcce90 b4ed5b1e 7e44fa90
    ];
    test_hmac_sha3_384_inner(&K[..104], "Sample message for keylen=blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 48] = [
        e5ae4c73 9f455279 368ebf36 d4f5354c
        95aa184c 899d3870 e460ebc2 88ef1f94
        70053f73 f7c6da2a 71bcaec3 8ce7d6ac
    ];
    test_hmac_sha3_384_inner(&K[..152], "Sample message for keylen>blocklen".as_bytes(), &d3[..]);

}

fn test_hmac_sha3_512() {

    let d1: [u8; 64] = [
        4efd629d 6c71bf86 162658f2 9943b1c3
        08ce27cd fa6db0d9 c3ce8176 3f9cbce5
        f7ebe986 8031db1a 8f8eb7b6 b95e5c5e
        3f657a89 96c86a2f 6527e307 f0213196
    ];
    test_hmac_sha3_512_inner(&K[..64], "Sample message for keylen<blocklen".as_bytes(), &d1[..]);

    let d2: [u8; 64] = [
        544e257e a2a3e5ea 19a590e6 a24b724c
        e6327757 723fe275 1b75bf00 7d80f6b3
        60744bf1 b7a88ea5 85f9765b 47911976
        d3191cf8 3c039f5f fab0d29c c9d9b6da
    ];
    test_hmac_sha3_512_inner(&K[..72], "Sample message for keylen=blocklen".as_bytes(), &d2[..]);

    let d3: [u8; 64] = [
        5f464f5e 5b7848e3 885e49b2 c385f069
        4985d0e3 8966242d c4a5fe3f ea4b37d4
        6b65cece d5dcf594 38dd840b ab22269f
        0ba7febd b9fcf746 02a35666 b2a32915
    ];
    test_hmac_sha3_512_inner(&K[..136], "Sample message for keylen>blocklen".as_bytes(), &d3[..]);

}

pub fn test_hmac_sha3_2() {
    test_hmac_sha3_3_224();
    test_hmac_sha3_3_256();
    test_hmac_sha3_3_384();
    test_hmac_sha3_3_512();
}