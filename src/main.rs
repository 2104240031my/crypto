mod crypto;

use std::env;
use crate::crypto::CryptoError;
use crate::crypto::cipher::BlockCipher128;
use crate::crypto::cipher::BlockCipher128Mode;
use crate::crypto::hash::Hash;
use crate::crypto::dh::Dh;
use crate::crypto::aes::Aes;
use crate::crypto::aes::AesAlgorithm;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::sha2::Sha512224;
use crate::crypto::sha2::Sha512256;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;
use crate::crypto::curve25519::Ed25519;
use crate::crypto::curve25519::X25519;

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("crypto command usage:");
        println!("    crypto [sub-command] ...");
        println!("");
        println!("list of sub-command is shown below:");
        println!(" - cipher");
        println!(" - hash");
        println!(" - help");
        return;
    }

    match args[1].as_str() {
        "hash" => {

            let mut flag: bool = false;

            if args.len() < 5 {

                println!("!Err: crypto hash commands takes at least 3 arguments.");

            } else {

                let (hash, md_len): (
                    fn (b: &[u8], d: &mut [u8]) -> Option<CryptoError>,
                    usize
                ) = match args[2].as_str() {
                    "sha-224"     => (Sha224::digest_oneshot, 28),
                    "sha-256"     => (Sha256::digest_oneshot, 32),
                    "sha-384"     => (Sha384::digest_oneshot, 48),
                    "sha-512"     => (Sha512::digest_oneshot, 64),
                    "sha-512/224" => (Sha512224::digest_oneshot, 28),
                    "sha-512/256" => (Sha512256::digest_oneshot, 32),
                    "sha3-224"    => (Sha3224::digest_oneshot, 28),
                    "sha3-256"    => (Sha3256::digest_oneshot, 32),
                    "sha3-384"    => (Sha3384::digest_oneshot, 48),
                    "sha3-512"    => (Sha3512::digest_oneshot, 64),
                    _             => (|b: &[u8], d: &mut [u8]| -> Option<CryptoError> {
                        return Some(CryptoError::new("!Err: the algorithm is not supported."));
                    }, 0)
                };

                match args[3].as_str() {
                    "str" => {
                        let mut out: [u8; 128] = [0; 128];
                        if let Some(e) = hash(args[4].as_bytes(), &mut out[..]) {
                        } else {
                            flag = true;
                            printlnbytes(&out[..md_len]);
                        }
                    },
                    _ => {}
                }

            }

            if !flag {
                println!("crypto hash command usage:");
                println!("    crypto hash [algorithm] [\"str\"|\"file\"] [in-data (string or file-path)] ...");
                println!("");
                println!("supported algorithms are shown below:");
                println!(" - sha-224");
                println!(" - sha-256");
                println!(" - sha-384");
                println!(" - sha-512");
                println!(" - sha-512/224");
                println!(" - sha-512/256");
                println!(" - sha3-224");
                println!(" - sha3-256");
                println!(" - sha3-384");
                println!(" - sha3-512");
            }

        },
        "test" => {
            test_aes();
            test_sha2();
            test_x25519();
            test_ed25519();
            return;
        }
        _ => return
    }

}

fn test_aes() {
    // let k = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    // let p = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    // let c = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
    // let k = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    // let p = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    // let c = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
    let k = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
    let p = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let c = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
    let mut out = [0; 16];
    let mut tag = [0; 16];
    let aes = Aes::new(AesAlgorithm::Aes256, &k[..]).unwrap();
    aes.encrypt(&p[..], &mut out[..]);
    printlnbytes(&out[..]);
    aes.decrypt(&c[..], &mut out[..]);
    printlnbytes(&out[..]);
    BlockCipher128Mode::ecb_encrypt(&aes, &p[..], &mut out[..]);
    printlnbytes(&out[..]);
    BlockCipher128Mode::ecb_decrypt(&aes, &c[..], &mut out[..]);
    printlnbytes(&out[..]);

    // BlockCipher128Mode::gcm_encrypt_generate(&aes, &p[..], &mut out[..]);
    // printlnbytes(&out[..]);
    // BlockCipher128Mode::gcm_decrypt_verify(&aes, &c[..], &mut out[..]);
    // printlnbytes(&out[..]);
}

fn test_sha2() {

    let bytes: [u8; 0] = [0; 0];
    let mut out: [u8; 64] = [0; 64];

    Sha224::digest_oneshot(&bytes[..], &mut out[..28]);
    printlnbytes(&out[..28]);
    Sha256::digest_oneshot(&bytes[..], &mut out[..32]);
    printlnbytes(&out[..32]);
    Sha384::digest_oneshot(&bytes[..], &mut out[..48]);
    printlnbytes(&out[..48]);
    Sha512::digest_oneshot(&bytes[..], &mut out[..64]);
    printlnbytes(&out[..64]);
    Sha512224::digest_oneshot(&bytes[..], &mut out[..28]);
    printlnbytes(&out[..28]);
    Sha512256::digest_oneshot(&bytes[..], &mut out[..32]);
    printlnbytes(&out[..32]);

    let mut sha2 = Sha224::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..28]);
    printlnbytes(&out[..28]);

    let mut sha2 = Sha256::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..32]);
    printlnbytes(&out[..32]);

    let mut sha2 = Sha384::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..48]);
    printlnbytes(&out[..48]);

    let mut sha2 = Sha512::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..64]);
    printlnbytes(&out[..64]);

    let mut sha2 = Sha512224::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..28]);
    printlnbytes(&out[..28]);

    let mut sha2 = Sha512256::new();
    sha2.update(&bytes[..]);
    sha2.digest(&mut out[..32]);
    printlnbytes(&out[..32]);

}

fn test_x25519() {

    // Test-Vector from RFC7748

    let alice_privkey: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    ];

    let bob_privkey: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    ];

    let alice_pubkey: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    ];

    let bob_pubkey: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    ];

    let shared_secret: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
    ];

    let mut out_alice_pubkey: [u8; 32] = [0; 32];
    let mut out_bob_pubkey: [u8; 32] = [0; 32];

    let mut out_alice_ss: [u8; 32] = [0; 32];
    let mut out_bob_ss: [u8; 32] = [0; 32];

    println!("Alice ECDH private key: ");
    printlnbytes(&alice_privkey[..]);

    println!("Bob ECDH private key: ");
    printlnbytes(&bob_privkey[..]);

    println!("Alice ECDH public key: ");
    X25519::compute_public_key(&alice_privkey[..], &mut out_alice_pubkey[..]);
    print!("  Test-V: "); printlnbytes(&alice_pubkey[..]);
    print!("  Result: "); printlnbytes(&out_alice_pubkey[..]);

    println!("Bob ECDH public key: ");
    X25519::compute_public_key(&bob_privkey[..], &mut out_bob_pubkey[..]);
    print!("  Test-V: "); printlnbytes(&bob_pubkey[..]);
    print!("  Result: "); printlnbytes(&out_bob_pubkey[..]);

    println!("Shared Secret: ");
    X25519::compute_shared_secret(&alice_privkey[..], &out_bob_pubkey[..], &mut out_alice_ss[..]);
    X25519::compute_shared_secret(&bob_privkey[..], &out_alice_pubkey[..], &mut out_bob_ss[..]);

    print!("  Test-V: ");  printlnbytes(&shared_secret[..]);
    println!("  Result: ");
    print!("    Alice: "); printlnbytes(&out_alice_ss[..]);
    print!("    Bob  : "); printlnbytes(&out_bob_ss[..]);

}

fn test_ed25519() {

    let privkey: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ];
    let msg: [u8; 32] = [0; 32];
    let mut sign: [u8; 32] = [0; 32];

    // Ed25519::sign(&privkey[..], &msg[..], &mut sign[..]);

}

fn printlnbytes(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}