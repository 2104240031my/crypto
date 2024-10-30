use crate::crypto::CryptoError;
use crate::crypto::DigitalSignature;
use crate::crypto::ed25519::Ed25519;
use crate::cmd::SuffixedArg;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    }

    if args.len() < 5 {
        println!("[!Err]: verify sub-command takes at least 4 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto verify help\".");
        return;
    }

    let (verify, verify_key_len, signature_len): (
        fn (a: &[u8], m: &[u8], s: &[u8]) -> Result<bool, CryptoError>,
        usize,
        usize
    ) = match args[1].as_str() {
        "ed25519" => (Ed25519::verify_oneshot, Ed25519::PUBLIC_KEY_LEN, Ed25519::SIGNATURE_LEN),
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which signature algorithms are supported, run \"crypto verify help\".");
            return;
        }
    };

    let verify_key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => {
            if v.len() != verify_key_len {
                println!("[!Err]: the length of verify key is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let msg: Vec<u8> = match SuffixedArg::to_bytes(args[3].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let signature: Vec<u8> = match SuffixedArg::to_bytes(args[4].as_str()) {
        Ok(v)  => {
            if v.len() != signature_len {
                println!("[!Err]: the length of signature is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    match verify(&verify_key, &msg, &signature) {
        Ok(v)  => {
            if v {
                println!("[Ok]: verification ok.")
            } else {
                println!("[!Err]: verification failed.")
            }
        },
        Err(_) => println!("[!Err]: verification failed."),
    }

}

fn println_subcmd_usage() {
    println!("verify sub-command usage:");
    println!("    crypto verify [algorithm] [verify-key (suffixed)] [message (suffixed)] [signature (suffixed)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - ed25519");
    println!("");
    println!("and enter verify-key, message, and signature as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}