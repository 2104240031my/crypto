use crate::crypto::util::Mac;
use crate::crypto::util::MacAlgorithm;
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
    } else if args.len() < 4 {
        println!("[!Err]: mac sub-command takes at least 3 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto mac help\".");
        return;
    }

    let algo: MacAlgorithm = match args[1].as_str() {
        "hmac-sha-224"  => MacAlgorithm::HmacSha224,
        "hmac-sha-256"  => MacAlgorithm::HmacSha256,
        "hmac-sha-384"  => MacAlgorithm::HmacSha384,
        "hmac-sha-512"  => MacAlgorithm::HmacSha512,
        "hmac-sha3-224" => MacAlgorithm::HmacSha3224,
        "hmac-sha3-256" => MacAlgorithm::HmacSha3256,
        "hmac-sha3-384" => MacAlgorithm::HmacSha3384,
        "hmac-sha3-512" => MacAlgorithm::HmacSha3512,
        "poly1305"      => MacAlgorithm::Poly1305,
        _               => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which MAC algorithms are supported, run \"crypto mac help\".");
            return;
        }
    };

    let Ok(key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    let Ok((in_fmt, in_src)) = SuffixedArg::parse_arg(args[3].as_str()).map_err(printerrln) else { return; };

    let mut mac_state: Mac = Mac::new(algo, &key).unwrap();

    let mut mac: [u8; 64] = [0; 64];
    match in_fmt {

        ArgType::Hexadecimal => {
            let msg: Vec<u8> = SuffixedArg::hexdec_to_bytes(in_src).unwrap();
            mac_state.update(&msg).unwrap();
        },

        ArgType::String      => {
            let msg: Vec<u8> = SuffixedArg::str_to_bytes(in_src).unwrap();
            mac_state.update(&msg).unwrap();
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
                        mac_state.update(&buf[..n]).unwrap();
                    }
                }
            }

        }

    }

    mac_state.compute(&mut mac[..algo.mac_len()]).unwrap();
    printbytesln(&mac[..algo.mac_len()]);

}

pub fn println_subcmd_usage() {
    println!("mac sub-command usage:");
    println!("    crypto mac [algorithm] [key (with suffix)] [message (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - hmac-sha-224");
    println!(" - hmac-sha-256");
    println!(" - hmac-sha-384");
    println!(" - hmac-sha-512");
    println!(" - hmac-sha3-224");
    println!(" - hmac-sha3-256");
    println!(" - hmac-sha3-384");
    println!(" - hmac-sha3-512");
    println!(" - poly1305");
    println!("");
    println!("and enter key and message as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}