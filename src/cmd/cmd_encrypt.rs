use crate::crypto::util::Cipher;
use crate::crypto::util::CipherAlgorithm;
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
    } else if args.len() < 6 {
        println!("[!Err]: encrypt sub-command takes at least 5 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto encrypt help\".");
        return;
    }

    let algo: CipherAlgorithm = match args[1].as_str() {
        "aes-128-ecb"     => CipherAlgorithm::Aes128Ecb,
        "aes-192-ecb"     => CipherAlgorithm::Aes192Ecb,
        "aes-256-ecb"     => CipherAlgorithm::Aes256Ecb,
        "aes-128-cbc"     => CipherAlgorithm::Aes128Cbc,
        "aes-192-cbc"     => CipherAlgorithm::Aes192Cbc,
        "aes-256-cbc"     => CipherAlgorithm::Aes256Cbc,
        "aes-128-cfb-8"   => CipherAlgorithm::Aes128CfbFb8,
        "aes-192-cfb-8"   => CipherAlgorithm::Aes192CfbFb8,
        "aes-256-cfb-8"   => CipherAlgorithm::Aes256CfbFb8,
        "aes-128-cfb-128" => CipherAlgorithm::Aes128CfbFb128,
        "aes-192-cfb-128" => CipherAlgorithm::Aes192CfbFb128,
        "aes-256-cfb-128" => CipherAlgorithm::Aes256CfbFb128,
        "aes-128-ofb"     => CipherAlgorithm::Aes128Ofb,
        "aes-192-ofb"     => CipherAlgorithm::Aes192Ofb,
        "aes-256-ofb"     => CipherAlgorithm::Aes256Ofb,
        "aes-128-ctr"     => CipherAlgorithm::Aes128Ctr,
        "aes-192-ctr"     => CipherAlgorithm::Aes192Ctr,
        "aes-256-ctr"     => CipherAlgorithm::Aes256Ctr,
        "chacha20"        => CipherAlgorithm::ChaCha20,
        _                 => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which cipher algorithms are supported, run \"crypto encrypt help\".");
            return;
        }
    };

    let Ok(key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if key.len() != algo.key_len() {
        println!("[!Err]: the length of key is too long or short.");
        return;
    }

    let Ok(mut iv) = SuffixedArg::to_bytes(args[3].as_str()).map_err(printerrln) else { return; };
    if iv.len() != algo.iv_len() {
        println!("[!Err]: the length of IV is too long or short.");
        return;
    }

    let Ok(pt) = SuffixedArg::to_bytes(args[4].as_str()).map_err(printerrln) else { return; };

    let mut ct: Vec<u8> = Vec::<u8>::with_capacity(pt.len());
    unsafe { ct.set_len(pt.len()); }

    let mut ciph: Cipher = Cipher::new(algo, &key).unwrap();
    ciph.encrypt(&mut iv, &pt, &mut ct).unwrap();

    let Ok((ct_fmt, ct_src)) = SuffixedArg::parse_arg(args[5].as_str()).map_err(printerrln) else { return; };
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
    println!("encrypt sub-command usage:");
    println!("    crypto encrypt [algorithm] [key (with suffix)] [iv (or icb, nonce, etc.) (with suffix)] [plaintext (with suffix)] [ciphertext (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - aes-128-ecb");
    println!(" - aes-192-ecb");
    println!(" - aes-256-ecb");
    println!(" - aes-128-cbc");
    println!(" - aes-192-cbc");
    println!(" - aes-256-cbc");
    println!(" - aes-128-cfb-8");
    println!(" - aes-192-cfb-8");
    println!(" - aes-256-cfb-8");
    println!(" - aes-128-cfb-8");
    println!(" - aes-192-cfb-128");
    println!(" - aes-256-cfb-128");
    println!(" - aes-128-ofb");
    println!(" - aes-192-ofb");
    println!(" - aes-256-ofb");
    println!(" - aes-128-ctr");
    println!(" - aes-192-ctr");
    println!(" - aes-256-ctr");
    println!(" - chacha20");
    println!("");
    println!("and enter key, iv, plaintext, and ciphertext as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}