use crate::crypto::Hash;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::sha2::Sha512224;
use crate::crypto::sha2::Sha512256;
use crate::test::{
    DEBUG_PRINT_SHA2,
    printbytesln,
    eqbytes
};

pub fn test_sha2() -> usize {
    let mut err: usize = 0;
    err = err + test_sha224();
    err = err + test_sha256();
    err = err + test_sha384();
    err = err + test_sha512();
    err = err + test_sha512224();
    err = err + test_sha512256();
    return err;
}

fn test_sha224_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 28] = [0; 28];
    let mut err: usize = 0;

    Sha224::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-224 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha224::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..28]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-224 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha256_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 32] = [0; 32];
    let mut err: usize = 0;

    Sha256::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha256::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..32]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha384_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 48] = [0; 48];
    let mut err: usize = 0;

    Sha384::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-384 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha384::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..48]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-384 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha512_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    Sha512::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha512::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..64]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha512224_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 28] = [0; 28];
    let mut err: usize = 0;

    Sha512224::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512224 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha512224::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..28]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512224 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha512256_inner(m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 32] = [0; 32];
    let mut err: usize = 0;

    Sha512256::digest_oneshot(m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut sha2 = Sha512256::new();
    sha2.reset().unwrap();
    for i in 0..m.len() {
        sha2.update(&m[i..(i + 1)]).unwrap();
    }
    sha2.digest(&mut out[..32]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_SHA2 {
        print!("[!Err]: testing SHA-512256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&d[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_sha224() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 28] = [
        0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22, 0x86, 0x42, 0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3,
        0x2A, 0xAD, 0xBC, 0xE4, 0xBD, 0xA0, 0xB3, 0xF7, 0xE3, 0x6C, 0x9D, 0xA7
    ];
    err = err + test_sha224_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let d2: [u8; 28] = [
        0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC, 0x5D, 0xBA, 0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50,
        0xB0, 0xC6, 0x45, 0x5C, 0xB4, 0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25
    ];
    err = err +test_sha224_inner(&m2[..], &d2[..]);

    return err;

}

fn test_sha256() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    ];
    err = err + test_sha256_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let d2: [u8; 32] = [
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
        0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1
    ];
    err = err + test_sha256_inner(&m2[..], &d2[..]);

    return err;

}

fn test_sha384() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 48] = [
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
        0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
        0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7
    ];
    err = err + test_sha384_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let d2: [u8; 48] = [
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B, 0x47,
        0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12,
        0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39
    ];
    err = err + test_sha384_inner(&m2[..], &d2[..]);

    return err;

}

fn test_sha512() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 64] = [
        0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
        0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
        0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
        0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E, 0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F
    ];
    err = err + test_sha512_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let d2: [u8; 64] = [
        0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
        0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
        0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
        0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54, 0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
    ];
    err = err + test_sha512_inner(&m2[..], &d2[..]);

    return err;

}

fn test_sha512224() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 28] = [
        0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08, 0x42, 0xE2,
        0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA
    ];
    err = err + test_sha512224_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let d2: [u8; 28] = [
        0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23, 0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C, 0x45, 0x33,
        0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72, 0x68, 0x67, 0x4A, 0xF9,
    ];
    err = err + test_sha512224_inner(&m2[..], &d2[..]);

    return err;

}

fn test_sha512256() -> usize {

    let mut err: usize = 0;

    let m1: &[u8] = "abc".as_bytes();
    let d1: [u8; 32] = [
        0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C, 0x7D, 0xAB,
        0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23
    ];
    err = err + test_sha512256_inner(&m1[..], &d1[..]);

    let m2: &[u8] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let d2: [u8; 32] = [
        0x39, 0x28, 0xE1, 0x84, 0xFB, 0x86, 0x90, 0xF8, 0x40, 0xDA, 0x39, 0x88, 0x12, 0x1D, 0x31, 0xBE,
        0x65, 0xCB, 0x9D, 0x3E, 0xF8, 0x3E, 0xE6, 0x14, 0x6F, 0xEA, 0xC8, 0x61, 0xE1, 0x9B, 0x56, 0x3A
    ];
    err = err + test_sha512256_inner(&m2[..], &d2[..]);

    return err;

}