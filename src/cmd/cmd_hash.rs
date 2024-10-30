use crate::crypto::CryptoError;
use crate::crypto::Hash;
use crate::crypto::sha2::Sha224;
use crate::crypto::sha2::Sha256;
use crate::crypto::sha2::Sha384;
use crate::crypto::sha2::Sha512;
use crate::crypto::sha2::Sha512224;
use crate::crypto::sha2::Sha512256;
use crate::crypto::sha3::Sha3224;
use crate::crypto::sha3::Sha3256;
use crate::crypto::sha3::Sha3384;
use crate::crypto::sha3::Sha3512;
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
    } else if args.len() < 3 {
        println!("[!Err]: hash sub-command takes at least 2 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto hash help\".");
        return;
    }

    let (mut ctx, md_len): (HashState, usize) = match args[1].as_str() {
        "sha-224"     => (HashState::Sha224(Sha224::new()), Sha224::MESSAGE_DIGEST_LEN),
        "sha-256"     => (HashState::Sha256(Sha256::new()), Sha256::MESSAGE_DIGEST_LEN),
        "sha-384"     => (HashState::Sha384(Sha384::new()), Sha384::MESSAGE_DIGEST_LEN),
        "sha-512"     => (HashState::Sha512(Sha512::new()), Sha512::MESSAGE_DIGEST_LEN),
        "sha-512-224" => (HashState::Sha512224(Sha512224::new()), Sha512224::MESSAGE_DIGEST_LEN),
        "sha-512-256" => (HashState::Sha512256(Sha512256::new()), Sha512256::MESSAGE_DIGEST_LEN),
        "sha3-224"    => (HashState::Sha3224(Sha3224::new()), Sha3224::MESSAGE_DIGEST_LEN),
        "sha3-256"    => (HashState::Sha3256(Sha3256::new()), Sha3256::MESSAGE_DIGEST_LEN),
        "sha3-384"    => (HashState::Sha3384(Sha3384::new()), Sha3384::MESSAGE_DIGEST_LEN),
        "sha3-512"    => (HashState::Sha3512(Sha3512::new()), Sha3512::MESSAGE_DIGEST_LEN),
        _             => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which hash algorithms are supported, run \"crypto hash help\".");
            return;
        }
    };

    let (in_fmt, in_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[2].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mut md: [u8; 64] = [0; 64];
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

    ctx.digest(&mut md[..md_len]).unwrap();
    printbytesln(&md[..md_len]);

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

enum HashState {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512224(Sha512224),
    Sha512256(Sha512256),
    Sha3224(Sha3224),
    Sha3256(Sha3256),
    Sha3384(Sha3384),
    Sha3512(Sha3512),
}

impl HashState {

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::Sha224(v)    => v.update(msg).err(),
            Self::Sha256(v)    => v.update(msg).err(),
            Self::Sha384(v)    => v.update(msg).err(),
            Self::Sha512(v)    => v.update(msg).err(),
            Self::Sha512224(v) => v.update(msg).err(),
            Self::Sha512256(v) => v.update(msg).err(),
            Self::Sha3224(v)   => v.update(msg).err(),
            Self::Sha3256(v)   => v.update(msg).err(),
            Self::Sha3384(v)   => v.update(msg).err(),
            Self::Sha3512(v)   => v.update(msg).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(self) };
    }

    fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::Sha224(v)    => v.digest(md).err(),
            Self::Sha256(v)    => v.digest(md).err(),
            Self::Sha384(v)    => v.digest(md).err(),
            Self::Sha512(v)    => v.digest(md).err(),
            Self::Sha512224(v) => v.digest(md).err(),
            Self::Sha512256(v) => v.digest(md).err(),
            Self::Sha3224(v)   => v.digest(md).err(),
            Self::Sha3256(v)   => v.digest(md).err(),
            Self::Sha3384(v)   => v.digest(md).err(),
            Self::Sha3512(v)   => v.digest(md).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(()) };
    }

}