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
use crate::cmd::BUFFER_SIZE;
use crate::cmd::printbytesln;
use std::fs::File;
use std::io::Read;

pub fn cmd_hash(args: Vec<String>) {

    if args.len() < 3 {
        println!("[!Err]: hash sub-command takes at least 2 arguments.\n");
        println_subcmd_usage();
        return;
    }

    let algo: String = args[1].clone();
    let in_data: String = args[2].clone();

    if in_data.len() < 2 {
        println!("[!Err]: invalid data format.");
        return;
    }

    let in_fmt: &str = &in_data[(in_data.len() - 2)..in_data.len()];
    let in_content: &str = &in_data[..(in_data.len() - 2)];

    let (mut ctx, md_len): (HashState, usize) = match algo.as_str() {
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
            println!("[!Err]: unsupported algorithm.\n");
            println_subcmd_usage();
            return;
        }
    };

    let mut md: [u8; 128] = [0; 128];
    match in_fmt {

        // hash the string
        ".s" => {

            if let Ok(_) = ctx.update(in_content.as_bytes()).unwrap().digest(&mut md[..]) {
                printbytesln(&md[..md_len]);
            }

        },

        // hash the file
        ".f" => {

            let mut buf: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

            let tmp = File::open(in_content);
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

            ctx.digest(&mut md[..]).unwrap();
            printbytesln(&md[..md_len]);

        },

        _ => {
            println!("[!Err]: uninterpretable data-fomat.\n");
            println_subcmd_usage();
            return;
        }

    }

}

pub fn println_subcmd_usage() {
    println!("hash sub-command usage:");
    println!("    crypto hash [algorithm] [in-data (with suffix): \"{{string}}.s\" | \"{{filepath}}.f\" ] ...");
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
    println!("and enter in-data as follows:");
    println!(" - if the input is the string \"abc\", enter \"abc.s\"");
    println!(" - if the input is the file \"efg.txt\", enter \"efg.txt.f\"");
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