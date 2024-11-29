use crate::crypto::util::DigitalSignatureAlgorithm;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;

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

    let algo: DigitalSignatureAlgorithm = match args[1].as_str() {
        "ed25519" => DigitalSignatureAlgorithm::Ed25519,
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which signature algorithms are supported, run \"crypto sign help\".");
            return;
        }
    };

    let Ok(sign_key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if sign_key.len() != algo.priv_key_len() {
        println!("[!Err]: the length of sign key is too long or short.");
        return;
    }

    let Ok(msg) = SuffixedArg::to_bytes(args[3].as_str()).map_err(printerrln) else { return; };

    let mut signature: [u8; 64] = [0; 64];
    algo.sign_oneshot(&sign_key, &msg, &mut signature[..algo.signature_len()]).unwrap();
    printbytesln(&signature[..algo.signature_len()]);

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