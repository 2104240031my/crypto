use crate::crypto::BlockCipher;
use crate::crypto::aes::AesAlgorithm;
use crate::crypto::aes::Aes;
use crate::test::{
    printbytesln,
    eqbytes
};

fn test_aes_128() {

    let k: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let p: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let c: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
    let mut out: [u8; 16] = [0; 16];
    let aes: Aes = Aes::new(AesAlgorithm::Aes128, &k[..]).unwrap();

    aes.encrypt(&p[..], &mut out[..]).unwrap();
    if !eqbytes(&c[..], &out[..]) {
        println!("Err: testing AES-128 is failed.");
        printbytesln(&c[..]);
        printbytesln(&out[..]);
    }

    aes.decrypt(&c[..], &mut out[..]).unwrap();
    if !eqbytes(&p[..], &out[..]) {
        println!("Err: testing AES-128 is failed.");
        printbytesln(&p[..]);
        printbytesln(&out[..]);
    }

}

pub fn test_aes() {
    test_aes_128();
}