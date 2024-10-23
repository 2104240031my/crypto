use crate::crypto::BlockCipher;
use crate::crypto::aes::AesAlgorithm;
use crate::crypto::aes::Aes;
use crate::test::{
    DEBUG_PRINT_AES,
    printbytesln,
    eqbytes
};

pub fn test_aes() -> usize {
    let mut err: usize = 0;
    err = err + test_aes_128_a();
    err = err + test_aes_128_b();
    err = err + test_aes_192();
    err = err + test_aes_256();
    return err;
}

fn test_aes_128_a() -> usize {

    let k: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let p: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let c: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes = Aes::new(AesAlgorithm::Aes128, &k[..]).unwrap();

    aes.encrypt(&p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    aes.decrypt(&c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_b() -> usize {

    let k: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let p: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let c: [u8; 16] = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes = Aes::new(AesAlgorithm::Aes128, &k[..]).unwrap();

    aes.encrypt(&p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    aes.decrypt(&c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192() -> usize {

    let k: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    ];
    let p: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let c: [u8; 16] = [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes = Aes::new(AesAlgorithm::Aes192, &k[..]).unwrap();

    aes.encrypt(&p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-192 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    aes.decrypt(&c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-192 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256() -> usize {

    let k: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ];
    let p: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let c: [u8; 16] = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes = Aes::new(AesAlgorithm::Aes256, &k[..]).unwrap();

    aes.encrypt(&p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    aes.decrypt(&c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES {
        print!("[!Err]: testing AES-256 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}