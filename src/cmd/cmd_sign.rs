use crate::crypto::CryptoError;
use crate::crypto::DigitalSignature;
use crate::crypto::ed25519::Ed25519;
use crate::cmd::SuffixedArg;
use crate::cmd::printbytesln;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    }

    if args.len() < 4 {
        println!("[!Err]: sign sub-command takes at least 3 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto sign help\".");
        return;
    }

    let (sign, sign_key_len, signature_len): (
        fn (k: &[u8], m: &[u8], s: &mut [u8]) -> Result<(), CryptoError>,
        usize,
        usize
    ) = match args[1].as_str() {
        "ed25519" => (Ed25519::sign_oneshot, Ed25519::PRIVATE_KEY_LEN, Ed25519::SIGNATURE_LEN),
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which signature algorithms are supported, run \"crypto sign help\".");
            return;
        }
    };

    let sign_key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => {
            if v.len() != sign_key_len {
                println!("[!Err]: the length of sign key is too long or short.");
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

    let mut signature: [u8; 64] = [0; 64];
    sign(&sign_key, &msg, &mut signature).unwrap();
    printbytesln(&signature[..signature_len]);

}

fn println_subcmd_usage() {
    println!("sign sub-command usage:");
    println!("    crypto sign [algorithm] [sign-key (suffixed)] [message (suffixed)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - ed25519");
    println!("");
    println!("and enter sign-key and message as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}