use crate::crypto::CryptoError;
use crate::crypto::CryptoErrorCode;
use crate::crypto::Hash;
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
use crate::cmd::printbytesln;

pub fn cmd_hash(args: Vec<String>) {

    let mut flag: bool = false;

    if args.len() < 4 {

        println!("!Err: crypto hash commands takes at least 3 arguments.");

    } else {

        let (hash, md_len): (
            fn (b: &[u8], d: &mut [u8]) -> Result<(), CryptoError>,
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
            _             => (|_b: &[u8], _d: &mut [u8]| -> Result<(), CryptoError> {
                return Err(CryptoError::new(CryptoErrorCode::UnsupportedAlgorithm));
            }, 0)
        };

        match args[3].as_str() {
            "str" => {
                let mut out: [u8; 128] = [0; 128];
                if let Ok(_) = hash(args[4].as_bytes(), &mut out[..]) {
                    flag = true;
                    printbytesln(&out[..md_len]);
                }
            },
            "file" => {

            }
            _ => {}
        }

    }

    if !flag {
        println!("crypto hash command usage:");
        println!("    crypto hash [algorithm] [\"str\"|\"file\"] [in-data (string or file-path)] ...");
        println!("");
        println!("supported algorithms are listed below:");
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

}