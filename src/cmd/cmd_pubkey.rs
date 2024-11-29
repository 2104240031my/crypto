use crate::crypto::ed25519::Ed25519;
use crate::crypto::error::CryptoError;
use crate::crypto::feature::DiffieHellman;
use crate::crypto::x25519::X25519;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 3 {
        println!("[!Err]: pubkey sub-command takes at least 2 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto pubkey help\".");
        return;
    }

    let (gen_pubkey, priv_key_len, pub_key_len): (
        fn (k: &[u8], a: &mut [u8]) -> Result<(), CryptoError>,
        usize,
        usize
    ) = match args[1].as_str() {
        "ed25519" => (Ed25519::compute_public_key_oneshot, Ed25519::PRIVATE_KEY_LEN, Ed25519::PUBLIC_KEY_LEN),
        "x25519"  => (X25519::compute_public_key_oneshot, X25519::PRIVATE_KEY_LEN, X25519::PUBLIC_KEY_LEN),
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which public-key cryptography algorithms are supported, run \"crypto pubkey help\".");
            return;
        }
    };

    let Ok(priv_key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if priv_key.len() != priv_key_len {
        println!("[!Err]: the length of private key is too long or short.");
        return;
    }

    let mut pub_key: [u8; 32] = [0; 32];
    gen_pubkey(&priv_key, &mut pub_key[..pub_key_len]).unwrap();
    printbytesln(&pub_key[..pub_key_len]);

}

fn println_subcmd_usage() {
    println!("pubkey sub-command usage:");
    println!("    crypto pubkey [algorithm] [private-key (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - ed25519");
    println!(" - x25519");
    println!("");
    println!("and enter private-key as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}