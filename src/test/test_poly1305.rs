use crate::crypto::Mac;
use crate::crypto::poly1305::Poly1305;
use crate::test::{
    DEBUG_PRINT_POLY1305,
    printbytesln,
    eqbytes
};

pub fn test_poly1305() -> usize {
    let mut err: usize = 0;
    err = err + test_poly1305_1();
    return err;
}

fn test_poly1305_inner(k: &[u8], m: &[u8], d: &[u8]) -> usize {

    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    Poly1305::compute_oneshot(k, m, &mut out[..]).unwrap();
    if !eqbytes(d, &out[..]) || DEBUG_PRINT_POLY1305 {
        print!("[!Err]: testing Poly1305 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(d);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    let mut poly1305 = Poly1305::new(k).unwrap();
    poly1305.reset().unwrap();
    for i in 0..m.len() {
        poly1305.update(&m[i..(i + 1)]).unwrap();
    }
    poly1305.compute(&mut out[..]).unwrap();

    if !eqbytes(d, &out[..]) || DEBUG_PRINT_POLY1305 {
        print!("[!Err]: testing Poly1305 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(d);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_poly1305_1() -> usize {

    let mut err: usize = 0;

    let k1: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    ];
    let m1: &[u8] = "Cryptographic Forum Research Group".as_bytes();
    let d1: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    ];
    err = err + test_poly1305_inner(&k1[..], &m1[..], &d1[..]);

    return err;

}