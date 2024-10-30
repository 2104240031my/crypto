use crate::crypto::CryptoError;
use crate::crypto::Mac;
use crate::crypto::hmac_sha2::HmacSha224;
use crate::crypto::hmac_sha2::HmacSha256;
use crate::crypto::hmac_sha2::HmacSha384;
use crate::crypto::hmac_sha2::HmacSha512;
use crate::crypto::hmac_sha3::HmacSha3224;
use crate::crypto::hmac_sha3::HmacSha3256;
use crate::crypto::hmac_sha3::HmacSha3384;
use crate::crypto::hmac_sha3::HmacSha3512;
use crate::cmd::ArgType;
use crate::cmd::SuffixedArg;
use crate::cmd::BUF_SIZE;
use crate::cmd::printbytesln;
use std::fs::File;
use std::io::Read;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 4 {
        println!("[!Err]: mac sub-command takes at least 3 arguments.\n");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto mac help\".");
        return;
    }

    let key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let (mut ctx, mac_len): (MacState, usize) = match args[1].as_str() {
        "hmac-sha-224"  => (MacState::HmacSha224(HmacSha224::new(&key[..]).unwrap()), HmacSha224::MAC_LEN),
        "hmac-sha-256"  => (MacState::HmacSha256(HmacSha256::new(&key[..]).unwrap()), HmacSha256::MAC_LEN),
        "hmac-sha-384"  => (MacState::HmacSha384(HmacSha384::new(&key[..]).unwrap()), HmacSha384::MAC_LEN),
        "hmac-sha-512"  => (MacState::HmacSha512(HmacSha512::new(&key[..]).unwrap()), HmacSha512::MAC_LEN),
        "hmac-sha3-224" => (MacState::HmacSha3224(HmacSha3224::new(&key[..]).unwrap()), HmacSha3224::MAC_LEN),
        "hmac-sha3-256" => (MacState::HmacSha3256(HmacSha3256::new(&key[..]).unwrap()), HmacSha3256::MAC_LEN),
        "hmac-sha3-384" => (MacState::HmacSha3384(HmacSha3384::new(&key[..]).unwrap()), HmacSha3384::MAC_LEN),
        "hmac-sha3-512" => (MacState::HmacSha3512(HmacSha3512::new(&key[..]).unwrap()), HmacSha3512::MAC_LEN),
        _               => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which MAC algorithms are supported, run \"crypto mac help\".");
            return;
        }
    };

    let (in_fmt, in_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[3].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mut mac: [u8; 64] = [0; 64];
    match in_fmt {

        ArgType::Hexadecimal => {
            let msg: Vec<u8> = SuffixedArg::hexdec_to_bytes(in_src).unwrap();
            ctx.update(&msg).unwrap();
        },

        ArgType::String      => {
            let msg: Vec<u8> = SuffixedArg::str_to_bytes(in_src).unwrap();
            ctx.update(&msg).unwrap();
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
                        ctx.update(&buf[..n]).unwrap();
                    }
                }
            }

        }

    }

    ctx.compute(&mut mac[..]).unwrap();
    printbytesln(&mac[..mac_len]);

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
    println!("");
    println!("and enter key and message as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}

enum MacState {
    HmacSha224(HmacSha224),
    HmacSha256(HmacSha256),
    HmacSha384(HmacSha384),
    HmacSha512(HmacSha512),
    HmacSha3224(HmacSha3224),
    HmacSha3256(HmacSha3256),
    HmacSha3384(HmacSha3384),
    HmacSha3512(HmacSha3512),
}

impl MacState {

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::HmacSha224(v)    => v.update(msg).err(),
            Self::HmacSha256(v)    => v.update(msg).err(),
            Self::HmacSha384(v)    => v.update(msg).err(),
            Self::HmacSha512(v)    => v.update(msg).err(),
            Self::HmacSha3224(v)   => v.update(msg).err(),
            Self::HmacSha3256(v)   => v.update(msg).err(),
            Self::HmacSha3384(v)   => v.update(msg).err(),
            Self::HmacSha3512(v)   => v.update(msg).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(self) };
    }

    fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::HmacSha224(v)    => v.compute(mac).err(),
            Self::HmacSha256(v)    => v.compute(mac).err(),
            Self::HmacSha384(v)    => v.compute(mac).err(),
            Self::HmacSha512(v)    => v.compute(mac).err(),
            Self::HmacSha3224(v)   => v.compute(mac).err(),
            Self::HmacSha3256(v)   => v.compute(mac).err(),
            Self::HmacSha3384(v)   => v.compute(mac).err(),
            Self::HmacSha3512(v)   => v.compute(mac).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(()) };
    }

}