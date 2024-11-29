use crate::crypto::util::Hash;
use crate::crypto::util::HashAlgorithm;
use crate::cmd::arg::ArgType;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::BUF_SIZE;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;
use std::fs::File;
use std::io::Read;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 3 {
        println!("[!Err]: hash sub-command takes at least 2 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto hash help\".");
        return;
    }

    let algo: HashAlgorithm = match args[1].as_str() {
        "sha-224"     => HashAlgorithm::Sha224,
        "sha-256"     => HashAlgorithm::Sha256,
        "sha-384"     => HashAlgorithm::Sha384,
        "sha-512"     => HashAlgorithm::Sha512,
        "sha-512-224" => HashAlgorithm::Sha512224,
        "sha-512-256" => HashAlgorithm::Sha512256,
        "sha3-224"    => HashAlgorithm::Sha3224,
        "sha3-256"    => HashAlgorithm::Sha3256,
        "sha3-384"    => HashAlgorithm::Sha3384,
        "sha3-512"    => HashAlgorithm::Sha3512,
        _             => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which hash algorithms are supported, run \"crypto hash help\".");
            return;
        }
    };

    let Ok((in_fmt, in_src)) = SuffixedArg::parse_arg(args[2].as_str()).map_err(printerrln) else { return; };

    let mut hash: Hash = Hash::new(algo);

    let mut md: [u8; 64] = [0; 64];
    match in_fmt {

        ArgType::Hexadecimal => {
            let msg: Vec<u8> = SuffixedArg::hexdec_to_bytes(in_src).unwrap();
            hash.update(&msg).unwrap();
        },

        ArgType::String      => {
            let msg: Vec<u8> = SuffixedArg::str_to_bytes(in_src).unwrap();
            hash.update(&msg).unwrap();
        },

        ArgType::Filepath    => {

            let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

            let tmp = File::open(in_src);
            if let Err(_) = tmp {
                println!("[!Err]: cannot open the file.");
                return;
            }
            let mut fs: File = tmp.unwrap();

            loop {
                match fs.read(&mut buf[..]).unwrap() {
                    0 => break,
                    n => {
                        hash.update(&buf[..n]).unwrap();
                    }
                }
            }

        }

    }

    hash.digest(&mut md[..algo.md_len()]).unwrap();
    printbytesln(&md[..algo.md_len()]);

}

pub fn println_subcmd_usage() {
    println!("hash sub-command usage:");
    println!("    crypto hash [algorithm] [message (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - sha-224");
    println!(" - sha-256");
    println!(" - sha-384");
    println!(" - sha-512");
    println!(" - sha-512-224");
    println!(" - sha-512-256");
    println!(" - sha3-224");
    println!(" - sha3-256");
    println!(" - sha3-384");
    println!(" - sha3-512");
    println!("");
    println!("and enter message as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}