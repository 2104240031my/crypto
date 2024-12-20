use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ecb128;
use crate::crypto::block_cipher_mode::Cbc128;
use crate::crypto::block_cipher_mode::Ofb128;
use crate::crypto::block_cipher_mode::Cfb128Fb8;
use crate::crypto::block_cipher_mode::Cfb128Fb128;
use crate::crypto::block_cipher_mode::Ctr128;
use crate::crypto::block_cipher_mode::Ccm128;
use crate::crypto::block_cipher_mode::Gcm128;
use crate::crypto::error::CryptoErrorCode;
use crate::test::{
    DEBUG_PRINT_AES_MODE,
    printbytesln,
    eqbytes
};

pub fn test_aes_mode() -> usize {
    let mut err: usize = 0;
    err = err + test_aes_128_ecb();
    err = err + test_aes_192_ecb();
    err = err + test_aes_256_ecb();
    err = err + test_aes_128_cbc();
    err = err + test_aes_192_cbc();
    err = err + test_aes_256_cbc();
    err = err + test_aes_128_cfb_fb8();
    err = err + test_aes_192_cfb_fb8();
    err = err + test_aes_256_cfb_fb8();
    err = err + test_aes_128_cfb_fb128();
    err = err + test_aes_192_cfb_fb128();
    err = err + test_aes_256_cfb_fb128();
    err = err + test_aes_128_ofb();
    err = err + test_aes_192_ofb();
    err = err + test_aes_256_ofb();
    err = err + test_aes_128_ctr();
    err = err + test_aes_192_ctr();
    err = err + test_aes_256_ctr();
    err = err + test_aes_128_ccm();
    err = err + test_aes_192_ccm();
    err = err + test_aes_256_ccm();
    err = err + test_aes_128_gcm();
    err = err + test_aes_192_gcm();
    err = err + test_aes_256_gcm();
    return err;
}

fn test_aes_128_ecb() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
        0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
        0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    BlockCipherMode128::ecb_encrypt_blocks(&aes, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::ecb_decrypt_blocks(&aes, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ecb_encrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ecb_decrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_ecb() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC,
        0x97, 0x41, 0x04, 0x84, 0x6D, 0x0A, 0xD3, 0xAD, 0x77, 0x34, 0xEC, 0xB3, 0xEC, 0xEE, 0x4E, 0xEF,
        0xEF, 0x7A, 0xFD, 0x22, 0x70, 0xE2, 0xE6, 0x0A, 0xDC, 0xE0, 0xBA, 0x2F, 0xAC, 0xE6, 0x44, 0x4E,
        0x9A, 0x4B, 0x41, 0xBA, 0x73, 0x8D, 0x6C, 0x72, 0xFB, 0x16, 0x69, 0x16, 0x03, 0xC1, 0x8E, 0x0E
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    BlockCipherMode128::ecb_encrypt_blocks(&aes, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::ecb_decrypt_blocks(&aes, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ecb_encrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ecb_decrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_ecb() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8,
        0x59, 0x1C, 0xCB, 0x10, 0xD4, 0x10, 0xED, 0x26, 0xDC, 0x5B, 0xA7, 0x4A, 0x31, 0x36, 0x28, 0x70,
        0xB6, 0xED, 0x21, 0xB9, 0x9C, 0xA6, 0xF4, 0xF9, 0xF1, 0x53, 0xE7, 0xB1, 0xBE, 0xAF, 0xED, 0x1D,
        0x23, 0x30, 0x4B, 0x7A, 0x39, 0xF9, 0xF3, 0xFF, 0x06, 0x7D, 0x8D, 0x8F, 0x9E, 0x24, 0xEC, 0xC7
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    BlockCipherMode128::ecb_encrypt_blocks(&aes, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::ecb_decrypt_blocks(&aes, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ecb_encrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ecb_decrypt_blocks_overwrite(&aes, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-ECB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_cbc() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let n: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
        0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
        0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    BlockCipherMode128::cbc_encrypt_blocks(&aes, &n[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::cbc_decrypt_blocks(&aes, &n[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cbc_encrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cbc_decrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_cbc() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let n: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x4F, 0x02, 0x1D, 0xB2, 0x43, 0xBC, 0x63, 0x3D, 0x71, 0x78, 0x18, 0x3A, 0x9F, 0xA0, 0x71, 0xE8,
        0xB4, 0xD9, 0xAD, 0xA9, 0xAD, 0x7D, 0xED, 0xF4, 0xE5, 0xE7, 0x38, 0x76, 0x3F, 0x69, 0x14, 0x5A,
        0x57, 0x1B, 0x24, 0x20, 0x12, 0xFB, 0x7A, 0xE0, 0x7F, 0xA9, 0xBA, 0xAC, 0x3D, 0xF1, 0x02, 0xE0,
        0x08, 0xB0, 0xE2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xD9, 0x20, 0xA9, 0xE6, 0x4F, 0x56, 0x15, 0xCD
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    BlockCipherMode128::cbc_encrypt_blocks(&aes, &n[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::cbc_decrypt_blocks(&aes, &n[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cbc_encrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cbc_decrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_cbc() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let n: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6,
        0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D,
        0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xB2, 0xEB, 0x05, 0xE2, 0xC3, 0x9B, 0xE9, 0xFC, 0xDA, 0x6C, 0x19, 0x07, 0x8C, 0x6A, 0x9D, 0x1B
    ];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    BlockCipherMode128::cbc_encrypt_blocks(&aes, &n[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    BlockCipherMode128::cbc_decrypt_blocks(&aes, &n[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cbc_encrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cbc_decrypt_blocks_overwrite(&aes, &n[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CBC is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_cfb_fb8() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let p: [u8; 16] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    ];
    let c: [u8; 16] = [
        0x3B, 0x79, 0x42, 0x4C, 0x9C, 0x0D, 0xD4, 0x36, 0xBA, 0xCE, 0x9E, 0x0E, 0xD4, 0x58, 0x6A, 0x4F
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb8_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb8_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_cfb_fb8() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let p: [u8; 16] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    ];
    let c: [u8; 16] = [
        0xCD, 0xA2, 0x52, 0x1E, 0xF0, 0xA9, 0x05, 0xCA, 0x44, 0xCD, 0x05, 0x7C, 0xBF, 0x0D, 0x47, 0xA0
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb8_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb8_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_cfb_fb8() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let p: [u8; 16] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    ];
    let c: [u8; 16] = [
        0xDC, 0x1F, 0x1A, 0x85, 0x20, 0xA6, 0x4D, 0xB5, 0x5F, 0xCC, 0x8A, 0xC5, 0x54, 0x84, 0x4E, 0x88
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb8_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb8_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb8_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-8 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_cfb_fb128() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
        0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B,
        0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF,
        0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb128_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb128_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_cfb_fb128() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB, 0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74,
        0x67, 0xCE, 0x7F, 0x7F, 0x81, 0x17, 0x36, 0x21, 0x96, 0x1A, 0x2B, 0x70, 0x17, 0x1D, 0x3D, 0x7A,
        0x2E, 0x1E, 0x8A, 0x1D, 0xD5, 0x9B, 0x88, 0xB1, 0xC8, 0xE6, 0x0F, 0xED, 0x1E, 0xFA, 0xC4, 0xC9,
        0xC0, 0x5F, 0x9F, 0x9C, 0xA9, 0x83, 0x4F, 0xA0, 0x42, 0xAE, 0x8F, 0xBA, 0x58, 0x4B, 0x09, 0xFF
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb128_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb128_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_cfb_fb128() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B, 0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
        0x39, 0xFF, 0xED, 0x14, 0x3B, 0x28, 0xB1, 0xC8, 0x32, 0x11, 0x3C, 0x63, 0x31, 0xE5, 0x40, 0x7B,
        0xDF, 0x10, 0x13, 0x24, 0x15, 0xE5, 0x4B, 0x92, 0xA1, 0x3E, 0xD0, 0xA8, 0x26, 0x7A, 0xE2, 0xF9,
        0x75, 0xA3, 0x85, 0x74, 0x1A, 0xB9, 0xCE, 0xF8, 0x20, 0x31, 0x62, 0x3D, 0x55, 0xB1, 0xE4, 0x71
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_encrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::cfb_fb128_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::cfb_fb128_encrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::cfb_fb128_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CFB-128 is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_ofb() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
        0x77, 0x89, 0x50, 0x8D, 0x16, 0x91, 0x8F, 0x03, 0xF5, 0x3C, 0x52, 0xDA, 0xC5, 0x4E, 0xD8, 0x25,
        0x97, 0x40, 0x05, 0x1E, 0x9C, 0x5F, 0xEC, 0xF6, 0x43, 0x44, 0xF7, 0xA8, 0x22, 0x60, 0xED, 0xCC,
        0x30, 0x4C, 0x65, 0x28, 0xF6, 0x59, 0xC7, 0x78, 0x66, 0xA5, 0x10, 0xD9, 0xC1, 0xD6, 0xAE, 0x5E
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_ofb() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB, 0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74,
        0xFC, 0xC2, 0x8B, 0x8D, 0x4C, 0x63, 0x83, 0x7C, 0x09, 0xE8, 0x17, 0x00, 0xC1, 0x10, 0x04, 0x01,
        0x8D, 0x9A, 0x9A, 0xEA, 0xC0, 0xF6, 0x59, 0x6F, 0x55, 0x9C, 0x6D, 0x4D, 0xAF, 0x59, 0xA5, 0xF2,
        0x6D, 0x9F, 0x20, 0x08, 0x57, 0xCA, 0x6C, 0x3E, 0x9C, 0xAC, 0x52, 0x4B, 0xD9, 0xAC, 0xC9, 0x2A
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_ofb() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B, 0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
        0x4F, 0xEB, 0xDC, 0x67, 0x40, 0xD2, 0x0B, 0x3A, 0xC8, 0x8F, 0x6A, 0xD8, 0x2A, 0x4F, 0xB0, 0x8D,
        0x71, 0xAB, 0x47, 0xA0, 0x86, 0xE8, 0x6E, 0xED, 0xF3, 0x9D, 0x1C, 0x5B, 0xBA, 0x97, 0xC4, 0x08,
        0x01, 0x26, 0x14, 0x1D, 0x67, 0xF3, 0x7B, 0xE8, 0x53, 0x8F, 0x5A, 0x8B, 0xE7, 0x40, 0xE4, 0x84
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    let mut sr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt(&aes, &mut sr[..], &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    sr.copy_from_slice(&iv[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ofb_encrypt_or_decrypt_overwrite(&aes, &mut sr[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-OFB is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_ctr() -> usize {

    let k: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6, 0xCE,
        0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF, 0xFD, 0xFF,
        0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D, 0xB0, 0x3E, 0xAB,
        0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0, 0xF3, 0x00, 0x9C, 0xEE
    ];
    let icb: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ];
    let mut ctr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_ctr() -> usize {

    let k: [u8; 24] = [
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x1A, 0xBC, 0x93, 0x24, 0x17, 0x52, 0x1C, 0xA2, 0x4F, 0x2B, 0x04, 0x59, 0xFE, 0x7E, 0x6E, 0x0B,
        0x09, 0x03, 0x39, 0xEC, 0x0A, 0xA6, 0xFA, 0xEF, 0xD5, 0xCC, 0xC2, 0xC6, 0xF4, 0xCE, 0x8E, 0x94,
        0x1E, 0x36, 0xB2, 0x6B, 0xD1, 0xEB, 0xC6, 0x70, 0xD1, 0xBD, 0x1D, 0x66, 0x56, 0x20, 0xAB, 0xF7,
        0x4F, 0x78, 0xA7, 0xF6, 0xD2, 0x98, 0x09, 0x58, 0x5A, 0x97, 0xDA, 0xEC, 0x58, 0xC6, 0xB0, 0x50
    ];
    let icb: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ];
    let mut ctr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_ctr() -> usize {

    let k: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    ];
    let p: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    ];
    let c: [u8; 64] = [
        0x60, 0x1E, 0xC3, 0x13, 0x77, 0x57, 0x89, 0xA5, 0xB7, 0xA7, 0xF5, 0x04, 0xBB, 0xF3, 0xD2, 0x28,
        0xF4, 0x43, 0xE3, 0xCA, 0x4D, 0x62, 0xB5, 0x9A, 0xCA, 0x84, 0xE9, 0x90, 0xCA, 0xCA, 0xF5, 0xC5,
        0x2B, 0x09, 0x30, 0xDA, 0xA2, 0x3D, 0xE9, 0x4C, 0xE8, 0x70, 0x17, 0xBA, 0x2D, 0x84, 0x98, 0x8D,
        0xDF, 0xC9, 0xC5, 0x8D, 0xB6, 0x7A, 0xAD, 0xA6, 0x13, 0xC2, 0xDD, 0x08, 0x45, 0x79, 0x41, 0xA6
    ];
    let icb: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ];
    let mut ctr: [u8; 16] = [0; 16];
    let mut out: [u8; 64] = [0; 64];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt(&aes, &mut ctr[..], 16, &c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&p[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&c[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    ctr.copy_from_slice(&icb[..]);
    out.copy_from_slice(&c[..]);
    BlockCipherMode128::ctr_encrypt_or_decrypt_overwrite(&aes, &mut ctr[..], 16, &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CTR is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out[..]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_ccm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    BlockCipherMode128::ccm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-128-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::ccm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-128-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_ccm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    BlockCipherMode128::ccm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-192-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::ccm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-192-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_ccm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    BlockCipherMode128::ccm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-256-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::ccm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::ccm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-256-CCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-CCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_ccm() -> usize {

    let k: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
    ];
    let n: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
    ];
    let a: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    ];
    let p: [u8; 64] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    ];
    let c1: [u8; 4] = [
        0x71, 0x62, 0x01, 0x5B
    ];
    let c2: [u8; 16] = [
        0xD2, 0xA1, 0xF0, 0xE0, 0x51, 0xEA, 0x5F, 0x62, 0x08, 0x1A, 0x77, 0x92, 0x07, 0x3D, 0x59, 0x3D
    ];
    let c3: [u8; 24] = [
        0xE3, 0xB2, 0x01, 0xA9, 0xF5, 0xB7, 0x1A, 0x7A, 0x9B, 0x1C, 0xEA, 0xEC, 0xCD, 0x97, 0xE7, 0x0B,
        0x61, 0x76, 0xAA, 0xD9, 0xA4, 0x42, 0x8A, 0xA5
    ];
    let c4: [u8; 64] = [
        0x71, 0x62, 0x01, 0x5B, 0xC0, 0x51, 0x95, 0x1E, 0x59, 0x18, 0xAE, 0xAF, 0x3C, 0x11, 0xF3, 0xD4,
        0xAC, 0x36, 0x3F, 0x8D, 0x5B, 0x6A, 0xF3, 0xD3, 0x69, 0x60, 0x3B, 0x04, 0xF2, 0x4C, 0xAE, 0x29,
        0x96, 0x4E, 0x2F, 0x2B, 0xF9, 0xD3, 0x11, 0x43, 0xF7, 0x25, 0x27, 0xCE, 0x2D, 0xB4, 0x02, 0xEA,
        0xB7, 0x66, 0x0E, 0x4A, 0x10, 0xB0, 0x8E, 0x82, 0x26, 0x65, 0x17, 0xCD, 0xF6, 0x02, 0x67, 0xF9
    ];
    let c5: [u8; 0] = [];
    let t1: [u8; 4] = [
        0x4D, 0xAC, 0x25, 0x5D
    ];
    let t2: [u8; 6] = [
        0x1F, 0xC6, 0x4F, 0xBF, 0xAC, 0xCD
    ];
    let t3: [u8; 8] = [
        0x48, 0x43, 0x92, 0xFB, 0xC1, 0xB0, 0x99, 0x51
    ];
    let t4: [u8; 4] = [
        0xC6, 0x6B, 0x65, 0x5C
    ];
    let t5: [u8; 4] = [
        0xE8, 0x40, 0x23, 0xF8
    ];
    let mut err: usize = 0;

    err = err + test_aes_128_ccm_inner(&k[..], &n[.. 7], &a[.. 8], &p[.. 4], &c1[..], &t1[..]);
    err = err + test_aes_128_ccm_inner(&k[..], &n[.. 8], &a[..16], &p[..16], &c2[..], &t2[..]);
    err = err + test_aes_128_ccm_inner(&k[..], &n[..12], &a[..20], &p[..24], &c3[..], &t3[..]);
    err = err + test_aes_128_ccm_inner(&k[..], &n[.. 7], &a[.. 0], &p[..64], &c4[..], &t4[..]);
    err = err + test_aes_128_ccm_inner(&k[..], &n[.. 7], &a[..64], &p[.. 0], &c5[..], &t5[..]);

    return err;

}

fn test_aes_192_ccm() -> usize {

    let k: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    ];
    let n: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
    ];
    let a: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    ];
    let p: [u8; 64] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    ];
    let c1: [u8; 4] = [
        0x18, 0xEE, 0x17, 0x30
    ];
    let c2: [u8; 16] = [
        0x22, 0x32, 0xB6, 0xE0, 0x92, 0x41, 0x48, 0xAE, 0x72, 0x39, 0xBC, 0xBD, 0x1A, 0x0F, 0x7E, 0xCB
    ];
    let c3: [u8; 24] = [
        0x80, 0x81, 0x31, 0x6F, 0xD8, 0x96, 0x24, 0xD6, 0x2C, 0xE7, 0x63, 0x7F, 0xB9, 0x49, 0x95, 0xB6,
        0x63, 0x1C, 0x50, 0xD6, 0x15, 0x86, 0xDE, 0x01
    ];
    let c4: [u8; 64] = [
        0x18, 0xEE, 0x17, 0x30, 0xF4, 0x49, 0x0E, 0xA8, 0x47, 0xA8, 0xE9, 0xC5, 0x32, 0xC6, 0x9F, 0x9C,
        0x0A, 0x53, 0x9A, 0x58, 0x5C, 0x1E, 0x7B, 0x6A, 0x5A, 0xF9, 0x19, 0xF4, 0x81, 0x90, 0x88, 0xA9,
        0x6E, 0xD6, 0x32, 0x55, 0x50, 0x98, 0xD3, 0x00, 0x7E, 0x7D, 0x96, 0x3C, 0x7B, 0xD0, 0x13, 0xEB,
        0x30, 0x76, 0x71, 0xD0, 0xFB, 0xC3, 0x9A, 0x0D, 0xF4, 0xA2, 0x6A, 0x9F, 0x4B, 0x9E, 0x4D, 0xAD
    ];
    let c5: [u8; 0] = [];
    let t1: [u8; 4] = [
        0xC8, 0xC3, 0x26, 0xD5
    ];
    let t2: [u8; 6] = [
        0x56, 0xE9, 0xCC, 0x28, 0xAA, 0x67
    ];
    let t3: [u8; 8] = [
        0x42, 0x36, 0x69, 0x52, 0x50, 0x5F, 0x99, 0x5A
    ];
    let t4: [u8; 4] = [
        0xC9, 0xCE, 0x2F, 0xBC
    ];
    let t5: [u8; 4] = [
        0xF1, 0xFB, 0x2A, 0x57
    ];
    let mut err: usize = 0;

    err = err + test_aes_192_ccm_inner(&k[..], &n[.. 7], &a[.. 8], &p[.. 4], &c1[..], &t1[..]);
    err = err + test_aes_192_ccm_inner(&k[..], &n[.. 8], &a[..16], &p[..16], &c2[..], &t2[..]);
    err = err + test_aes_192_ccm_inner(&k[..], &n[..12], &a[..20], &p[..24], &c3[..], &t3[..]);
    err = err + test_aes_192_ccm_inner(&k[..], &n[.. 7], &a[.. 0], &p[..64], &c4[..], &t4[..]);
    err = err + test_aes_192_ccm_inner(&k[..], &n[.. 7], &a[..64], &p[.. 0], &c5[..], &t5[..]);

    return err;

}

fn test_aes_256_ccm() -> usize {

    let k: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    ];
    let n: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
    ];
    let a: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    ];
    let p: [u8; 64] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    ];
    let c1: [u8; 4] = [
        0x8A, 0xB1, 0xA8, 0x74
    ];
    let c2: [u8; 16] = [
        0xAF, 0x17, 0x85, 0xFC, 0x0F, 0x5E, 0xA7, 0xD0, 0xCF, 0xBA, 0x83, 0x72, 0x46, 0x48, 0x44, 0x97
    ];
    let c3: [u8; 24] = [
        0x04, 0xF8, 0x83, 0xAE, 0xB3, 0xBD, 0x07, 0x30, 0xEA, 0xF5, 0x0B, 0xB6, 0xDE, 0x4F, 0xA2, 0x21,
        0x20, 0x34, 0xE4, 0xE4, 0x1B, 0x0E, 0x75, 0xE5
    ];
    let c4: [u8; 64] = [
        0x8A, 0xB1, 0xA8, 0x74, 0xF6, 0x85, 0x3F, 0x24, 0x43, 0xA5, 0x95, 0x00, 0xF7, 0x8D, 0x17, 0x27,
        0x2D, 0x6D, 0x39, 0xDF, 0xA6, 0xD0, 0xE6, 0x51, 0x07, 0xB1, 0x07, 0x00, 0xC2, 0xCE, 0x9E, 0xE8,
        0x66, 0x3D, 0x3E, 0x2A, 0x01, 0xC2, 0xE1, 0x2C, 0x32, 0xE9, 0x37, 0x74, 0x42, 0x23, 0x19, 0x20,
        0xBE, 0x53, 0x27, 0x8F, 0x4F, 0x60, 0xA9, 0x72, 0xB7, 0x09, 0xBB, 0x16, 0x93, 0x29, 0x36, 0xBA
    ];
    let c5: [u8; 0] = [];
    let t1: [u8; 4] = [
        0x95, 0xFC, 0x08, 0x20
    ];
    let t2: [u8; 6] = [
        0x94, 0xB8, 0x26, 0xC8, 0x84, 0x9E
    ];
    let t3: [u8; 8] = [
        0x2B, 0x48, 0xC8, 0x76, 0x6F, 0x7E, 0x76, 0x49
    ];
    let t4: [u8; 4] = [
        0x3F, 0xBD, 0x0F, 0xAE
    ];
    let t5: [u8; 4] = [
        0xA6, 0xCF, 0x82, 0x30
    ];
    let mut err: usize = 0;

    err = err + test_aes_256_ccm_inner(&k[..], &n[.. 7], &a[.. 8], &p[.. 4], &c1[..], &t1[..]);
    err = err + test_aes_256_ccm_inner(&k[..], &n[.. 8], &a[..16], &p[..16], &c2[..], &t2[..]);
    err = err + test_aes_256_ccm_inner(&k[..], &n[..12], &a[..20], &p[..24], &c3[..], &t3[..]);
    err = err + test_aes_256_ccm_inner(&k[..], &n[.. 7], &a[.. 0], &p[..64], &c4[..], &t4[..]);
    err = err + test_aes_256_ccm_inner(&k[..], &n[.. 7], &a[..64], &p[.. 0], &c5[..], &t5[..]);

    return err;

}

fn test_aes_128_gcm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes128 = Aes128::new(&k[..]).unwrap();

    BlockCipherMode128::gcm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-128-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::gcm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-128-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-128-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_192_gcm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes192 = Aes192::new(&k[..]).unwrap();

    BlockCipherMode128::gcm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-192-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::gcm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-192-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-192-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_256_gcm_inner(k: &[u8], n: &[u8], a: &[u8], p: &[u8], c: &[u8], t: &[u8]) -> usize {

    let mut out1: [u8; 64] = [0; 64];
    let mut out2: [u8; 16] = [0; 16];
    let mut err: usize = 0;

    let aes: Aes256 = Aes256::new(&k[..]).unwrap();

    BlockCipherMode128::gcm_encrypt_and_generate(
        &aes, n, a, p, &mut out1[..c.len()], &mut out2[..]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify(
        &aes, n, a, c, &mut out1[..p.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-256-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    out1[..p.len()].copy_from_slice(&p[..]);
    BlockCipherMode128::gcm_encrypt_and_generate_overwrite(
        &aes, n, a, &mut out1[..p.len()], &mut out2[..t.len()]
    ).unwrap();
    if !eqbytes(c, &out1[..c.len()]) || !eqbytes(t, &out2[..t.len()]) || DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Test-Vec => {{\n");
        print!("       CT : "); printbytesln(c);
        print!("       TAG: "); printbytesln(t);
        print!("   }}\n");
        print!(" - Exec-Res => {{\n");
        print!("       CT : "); printbytesln(&out1[..c.len()]);
        print!("       TAG: "); printbytesln(&out2[..t.len()]);
        print!("   }}\n");
        println!();
        err = err + 1;
    }

    out1[..c.len()].copy_from_slice(&c[..]);
    if let Err(e) = BlockCipherMode128::gcm_decrypt_and_verify_overwrite(
        &aes, n, a, &mut out1[..c.len()], t
    ) {
        match e.err_code() {
            CryptoErrorCode::VerificationFailed => {
                print!("[!Err]: testing AES-256-GCM is FAILED.\n");
                print!(" - Verification FAILED.\n");
                println!();
            },
            _ => {
                panic!("{}", e);
            }
        }
        err = err + 1;
    } else if !eqbytes(p, &out1[..p.len()]) {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Decryption FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    } else if DEBUG_PRINT_AES_MODE {
        print!("[!Err]: testing AES-256-GCM is FAILED.\n");
        print!(" - Test-Vec => "); printbytesln(&p[..]);
        print!(" - Exec-Res => "); printbytesln(&out1[..p.len()]);
        println!();
        err = err + 1;
    }

    return err;

}

fn test_aes_128_gcm() -> usize {

    let k: [u8; 16] = [
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08
    ];
    let n: [u8; 12] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    ];
    let a: [u8; 64] = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
        0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
        0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
    ];
    let p: [u8; 64] = [
        0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A,
        0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72,
        0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
        0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39, 0x1A, 0xAF, 0xD2, 0x55
    ];
    let c: [u8; 64] = [
        0x42, 0x83, 0x1E, 0xC2, 0x21, 0x77, 0x74, 0x24, 0x4B, 0x72, 0x21, 0xB7, 0x84, 0xD0, 0xD4, 0x9C,
        0xE3, 0xAA, 0x21, 0x2F, 0x2C, 0x02, 0xA4, 0xE0, 0x35, 0xC1, 0x7E, 0x23, 0x29, 0xAC, 0xA1, 0x2E,
        0x21, 0xD5, 0x14, 0xB2, 0x54, 0x66, 0x93, 0x1C, 0x7D, 0x8F, 0x6A, 0x5A, 0xAC, 0x84, 0xAA, 0x05,
        0x1B, 0xA3, 0x0B, 0x39, 0x6A, 0x0A, 0xAC, 0x97, 0x3D, 0x58, 0xE0, 0x91, 0x47, 0x3F, 0x59, 0x85
    ];
    let t1: [u8; 16] = [
        0x32, 0x47, 0x18, 0x4B, 0x3C, 0x4F, 0x69, 0xA4, 0x4D, 0xBC, 0xD2, 0x28, 0x87, 0xBB, 0xB4, 0x18
    ];
    let t2: [u8; 16] = [
        0x4D, 0x5C, 0x2A, 0xF3, 0x27, 0xCD, 0x64, 0xA6, 0x2C, 0xF3, 0x5A, 0xBD, 0x2B, 0xA6, 0xFA, 0xB4
    ];
    let t3: [u8; 16] = [
        0x5F, 0x91, 0xD7, 0x71, 0x23, 0xEF, 0x5E, 0xB9, 0x99, 0x79, 0x13, 0x84, 0x9B, 0x8D, 0xC1, 0xE9
    ];
    let t4: [u8; 16] = [
        0x64, 0xC0, 0x23, 0x29, 0x04, 0xAF, 0x39, 0x8A, 0x5B, 0x67, 0xC1, 0x0B, 0x53, 0xA5, 0x02, 0x4D
    ];
    let t5: [u8; 16] = [
        0xF0, 0x7C, 0x25, 0x28, 0xEE, 0xA2, 0xFC, 0xA1, 0x21, 0x1F, 0x90, 0x5E, 0x1B, 0x6A, 0x88, 0x1B
    ];
    let mut err: usize = 0;

    err = err + test_aes_128_gcm_inner(&k[..], &n[..], &a[..0],  &p[..0],  &c[..0],  &t1[..]);
    err = err + test_aes_128_gcm_inner(&k[..], &n[..], &a[..0],  &p[..64], &c[..64], &t2[..]);
    err = err + test_aes_128_gcm_inner(&k[..], &n[..], &a[..64], &p[..0],  &c[..0],  &t3[..]);
    err = err + test_aes_128_gcm_inner(&k[..], &n[..], &a[..64], &p[..64], &c[..64], &t4[..]);
    err = err + test_aes_128_gcm_inner(&k[..], &n[..], &a[..20], &p[..60], &c[..60], &t5[..]);

    return err;

}

fn test_aes_192_gcm() -> usize {

    let k: [u8; 24] = [
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C
    ];
    let n: [u8; 12] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    ];
    let a: [u8; 64] = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
        0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
        0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
    ];
    let p: [u8; 64] = [
        0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A,
        0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72,
        0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
        0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39, 0x1A, 0xAF, 0xD2, 0x55
    ];
    let c: [u8; 64] = [
        0x39, 0x80, 0xCA, 0x0B, 0x3C, 0x00, 0xE8, 0x41, 0xEB, 0x06, 0xFA, 0xC4, 0x87, 0x2A, 0x27, 0x57,
        0x85, 0x9E, 0x1C, 0xEA, 0xA6, 0xEF, 0xD9, 0x84, 0x62, 0x85, 0x93, 0xB4, 0x0C, 0xA1, 0xE1, 0x9C,
        0x7D, 0x77, 0x3D, 0x00, 0xC1, 0x44, 0xC5, 0x25, 0xAC, 0x61, 0x9D, 0x18, 0xC8, 0x4A, 0x3F, 0x47,
        0x18, 0xE2, 0x44, 0x8B, 0x2F, 0xE3, 0x24, 0xD9, 0xCC, 0xDA, 0x27, 0x10, 0xAC, 0xAD, 0xE2, 0x56
    ];
    let t1: [u8; 16] = [
        0xC8, 0x35, 0xAA, 0x88, 0xAE, 0xBB, 0xC9, 0x4F, 0x5A, 0x02, 0xE1, 0x79, 0xFD, 0xCF, 0xC3, 0xE4
    ];
    let t2: [u8; 16] = [
        0x99, 0x24, 0xA7, 0xC8, 0x58, 0x73, 0x36, 0xBF, 0xB1, 0x18, 0x02, 0x4D, 0xB8, 0x67, 0x4A, 0x14
    ];
    let t3: [u8; 16] = [
        0x02, 0xCC, 0x77, 0x3B, 0xC9, 0x19, 0xF4, 0xE1, 0xC5, 0xE9, 0xC5, 0x43, 0x13, 0xBF, 0xAC, 0xE0
    ];
    let t4: [u8; 16] = [
        0x3B, 0x91, 0x53, 0xB4, 0xE7, 0x31, 0x8A, 0x5F, 0x3B, 0xBE, 0xAC, 0x10, 0x8F, 0x8A, 0x8E, 0xDB
    ];
    let t5: [u8; 16] = [
        0x93, 0xEA, 0x28, 0xC6, 0x59, 0xE2, 0x69, 0x90, 0x2A, 0x80, 0xAC, 0xD2, 0x08, 0xE7, 0xFC, 0x80
    ];
    let mut err: usize = 0;

    err = err + test_aes_192_gcm_inner(&k[..], &n[..], &a[..0],  &p[..0],  &c[..0],  &t1[..]);
    err = err + test_aes_192_gcm_inner(&k[..], &n[..], &a[..0],  &p[..64], &c[..64], &t2[..]);
    err = err + test_aes_192_gcm_inner(&k[..], &n[..], &a[..64], &p[..0],  &c[..0],  &t3[..]);
    err = err + test_aes_192_gcm_inner(&k[..], &n[..], &a[..64], &p[..64], &c[..64], &t4[..]);
    err = err + test_aes_192_gcm_inner(&k[..], &n[..], &a[..20], &p[..60], &c[..60], &t5[..]);

    return err;

}

fn test_aes_256_gcm() -> usize {

    let k: [u8; 32] = [
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08
    ];
    let n: [u8; 12] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    ];
    let a: [u8; 64] = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
        0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
        0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
    ];
    let p: [u8; 64] = [
        0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A,
        0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72,
        0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
        0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39, 0x1A, 0xAF, 0xD2, 0x55
    ];
    let c: [u8; 64] = [
        0x52, 0x2D, 0xC1, 0xF0, 0x99, 0x56, 0x7D, 0x07, 0xF4, 0x7F, 0x37, 0xA3, 0x2A, 0x84, 0x42, 0x7D,
        0x64, 0x3A, 0x8C, 0xDC, 0xBF, 0xE5, 0xC0, 0xC9, 0x75, 0x98, 0xA2, 0xBD, 0x25, 0x55, 0xD1, 0xAA,
        0x8C, 0xB0, 0x8E, 0x48, 0x59, 0x0D, 0xBB, 0x3D, 0xA7, 0xB0, 0x8B, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xC5, 0xF6, 0x1E, 0x63, 0x93, 0xBA, 0x7A, 0x0A, 0xBC, 0xC9, 0xF6, 0x62, 0x89, 0x80, 0x15, 0xAD
    ];
    let t1: [u8; 16] = [
        0xFD, 0x2C, 0xAA, 0x16, 0xA5, 0x83, 0x2E, 0x76, 0xAA, 0x13, 0x2C, 0x14, 0x53, 0xEE, 0xDA, 0x7E
    ];
    let t2: [u8; 16] = [
        0xB0, 0x94, 0xDA, 0xC5, 0xD9, 0x34, 0x71, 0xBD, 0xEC, 0x1A, 0x50, 0x22, 0x70, 0xE3, 0xCC, 0x6C
    ];
    let t3: [u8; 16] = [
        0xDE, 0x34, 0xB6, 0xDC, 0xD4, 0xCE, 0xE2, 0xFD, 0xBE, 0xC3, 0xCE, 0xA0, 0x1A, 0xF1, 0xEE, 0x44
    ];
    let t4: [u8; 16] = [
        0xC0, 0x6D, 0x76, 0xF3, 0x19, 0x30, 0xFE, 0xF3, 0x7A, 0xCA, 0xE2, 0x3E, 0xD4, 0x65, 0xAE, 0x62
    ];
    let t5: [u8; 16] = [
        0xE0, 0x97, 0x19, 0x5F, 0x45, 0x32, 0xDA, 0x89, 0x5F, 0xB9, 0x17, 0xA5, 0xA5, 0x5C, 0x6A, 0xA0
    ];
    let mut err: usize = 0;

    err = err + test_aes_256_gcm_inner(&k[..], &n[..], &a[..0],  &p[..0],  &c[..0],  &t1[..]);
    err = err + test_aes_256_gcm_inner(&k[..], &n[..], &a[..0],  &p[..64], &c[..64], &t2[..]);
    err = err + test_aes_256_gcm_inner(&k[..], &n[..], &a[..64], &p[..0],  &c[..0],  &t3[..]);
    err = err + test_aes_256_gcm_inner(&k[..], &n[..], &a[..64], &p[..64], &c[..64], &t4[..]);
    err = err + test_aes_256_gcm_inner(&k[..], &n[..], &a[..20], &p[..60], &c[..60], &t5[..]);

    return err;

}