use crate::crypto::util::Aead;
use crate::crypto::util::AeadAlgorithm;
use crate::cmd::arg::ArgType;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;
use std::fs::File;
use std::io::Write;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 7 {
        println!("[!Err]: seal sub-command takes at least 6 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto seal help\".");
        return;
    }

    let algo: AeadAlgorithm = match args[1].as_str() {
        "aes-128-ccm"       => AeadAlgorithm::Aes128Ccm,
        "aes-192-ccm"       => AeadAlgorithm::Aes192Ccm,
        "aes-256-ccm"       => AeadAlgorithm::Aes256Ccm,
        "aes-128-gcm"       => AeadAlgorithm::Aes128Gcm,
        "aes-192-gcm"       => AeadAlgorithm::Aes192Gcm,
        "aes-256-gcm"       => AeadAlgorithm::Aes256Gcm,
        "chacha20-poly1305" => AeadAlgorithm::ChaCha20Poly1305,
        _                   => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which aead algorithms are supported, run \"crypto seal help\".");
            return;
        }
    };

    let Ok(key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if key.len() != algo.key_len() {
        println!("[!Err]: the length of key is too long or short.");
        return;
    }

    let Ok(mut nonce) = SuffixedArg::to_bytes(args[3].as_str()).map_err(printerrln) else { return; };
    if nonce.len() < algo.min_nonce_len() || nonce.len() > algo.max_nonce_len() {
        println!("[!Err]: the length of nonce is too long or short.");
        return;
    }

    let Ok(aad) = SuffixedArg::to_bytes(args[4].as_str()).map_err(printerrln) else { return; };
    let Ok(pt)  = SuffixedArg::to_bytes(args[5].as_str()).map_err(printerrln) else { return; };

    let mut tag: [u8; 16] = [0; 16];
    let tlen: usize = algo.tag_len();

    let mut ct: Vec<u8> = Vec::<u8>::with_capacity(pt.len() + tlen);
    unsafe { ct.set_len(pt.len()); }

    let mut aead: Aead = Aead::new(algo, &key).unwrap();
    aead.encrypt_and_generate(&mut nonce, &aad, &pt, &mut ct, &mut tag[..tlen]).unwrap();
    for t in &tag[..tlen] {
        ct.push(*t);
    }

    let Ok((ct_fmt, ct_src)) = SuffixedArg::parse_arg(args[6].as_str()).map_err(printerrln) else { return; };
    match ct_fmt {
        ArgType::Hexadecimal => printbytesln(&ct),
        ArgType::String      => println!("{}", match std::str::from_utf8(&ct) {
            Ok(v)  => v,
            Err(_) => {
                println!("[!Err]: cannot convert to UTF-8.");
                return;
            }
        }),
        ArgType::Filepath    => {
            let tmp = File::create(ct_src);
            if let Err(_) = tmp {
                println!("[!Err]: cannot open the file.");
                return;
            }
            if let Err(_) = tmp.unwrap().write_all(&ct) {
                println!("[!Err]: an error occurred while writing data to file.");
                return;
            }
        }
    }

}

pub fn println_subcmd_usage() {
    println!("seal sub-command usage:");
    println!("    crypto seal [algorithm] [key (with suffix)] [nonce (with suffix)] [aad (with suffix)] [plaintext (with suffix)] [ciphertext (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - aes-128-ccm");
    println!(" - aes-192-ccm");
    println!(" - aes-256-ccm");
    println!(" - aes-128-gcm");
    println!(" - aes-192-gcm");
    println!(" - aes-256-gcm");
    println!(" - chacha20-poly1305");
    println!("");
    println!("and enter key, nonce, aad, plaintext, and ciphertext as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}