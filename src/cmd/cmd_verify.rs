use crate::crypto::util::DigitalSignatureAlgorithm;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::printerrln;

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

    let algo: DigitalSignatureAlgorithm = match args[1].as_str() {
        "ed25519" => DigitalSignatureAlgorithm::Ed25519,
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which signature algorithms are supported, run \"crypto verify help\".");
            return;
        }
    };

    let Ok(verify_key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if verify_key.len() != algo.pub_key_len() {
        println!("[!Err]: the length of verify key is too long or short.");
        return;
    }

    let Ok(msg) = SuffixedArg::to_bytes(args[3].as_str()).map_err(printerrln) else { return; };

    let Ok(signature) = SuffixedArg::to_bytes(args[4].as_str()).map_err(printerrln) else { return; };
    if signature.len() != algo.signature_len() {
        println!("[!Err]: the length of signature is too long or short.");
        return;
    }

    match algo.verify_oneshot(&verify_key, &msg, &signature) {
        Ok(v)  => println!("{}", if v { "[Ok]: verification ok." } else { "[!Err]: verification failed." }),
        Err(_) => println!("[!Err]: verification failed.")
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