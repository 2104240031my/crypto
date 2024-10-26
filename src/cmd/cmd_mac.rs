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
use crate::cmd::BUFFER_SIZE;
use crate::cmd::printbytesln;
use std::fs::File;
use std::io::Read;

pub fn cmd_mac(args: Vec<String>) {

    if args.len() < 4 {
        println!("[!Err]: mac sub-command takes at least 3 arguments.\n");
        println_subcmd_usage();
        return;
    }

    let algo: String = args[1].clone();
    let key: String = args[2].clone();
    let in_data: String = args[3].clone();

    if key.len() < 2 || in_data.len() < 2 {
        println!("[!Err]: invalid data format.");
        return;
    }

    let key_fmt: &str = &key[(key.len() - 2)..key.len()];
    let key_content: &str = &key[..(key.len() - 2)];
    let in_fmt: &str = &in_data[(in_data.len() - 2)..in_data.len()];
    let in_content: &str = &in_data[..(in_data.len() - 2)];

    let mut key: [u8; 65536] = [0; 65536];
    match key_fmt {

        ".s" => {

            let tmp: &[u8] = key_content.as_bytes();

            if tmp.len() > key.len() {
                println!("[!Err]: the key is too long.");
                return;
            }

            key[..tmp.len()].copy_from_slice(tmp);

        },

        ".f" => {

            let tmp = File::open(key_content);
            if let Err(_) = tmp {
                println!("[!Err]: cannot open the file.");
                return;
            }
            let mut fs: File = tmp.unwrap();

            let mut r: usize = 0;
            loop {
                match fs.read(&mut key[r..]).unwrap() {
                    0 => break,
                    n => {
                        r = r + n;
                        if r >= key.len() {
                            println!("[!Err]: cannot open the file.");
                            return;
                        }
                    }
                }
            }

        },

        _ => {
            println!("[!Err]: uninterpretable data-fomat.\n");
            println_subcmd_usage();
            return;
        }

    }

    let (mut ctx, mac_len): (MacState, usize) = match algo.as_str() {
        "hmac-sha-224"  => (MacState::HmacSha224(HmacSha224::new(&key[..]).unwrap()), HmacSha224::MAC_LEN),
        "hmac-sha-256"  => (MacState::HmacSha256(HmacSha256::new(&key[..]).unwrap()), HmacSha256::MAC_LEN),
        "hmac-sha-384"  => (MacState::HmacSha384(HmacSha384::new(&key[..]).unwrap()), HmacSha384::MAC_LEN),
        "hmac-sha-512"  => (MacState::HmacSha512(HmacSha512::new(&key[..]).unwrap()), HmacSha512::MAC_LEN),
        "hmac-sha3-224" => (MacState::HmacSha3224(HmacSha3224::new(&key[..]).unwrap()), HmacSha3224::MAC_LEN),
        "hmac-sha3-256" => (MacState::HmacSha3256(HmacSha3256::new(&key[..]).unwrap()), HmacSha3256::MAC_LEN),
        "hmac-sha3-384" => (MacState::HmacSha3384(HmacSha3384::new(&key[..]).unwrap()), HmacSha3384::MAC_LEN),
        "hmac-sha3-512" => (MacState::HmacSha3512(HmacSha3512::new(&key[..]).unwrap()), HmacSha3512::MAC_LEN),
        _               => {
            println!("[!Err]: unsupported algorithm.\n");
            println_subcmd_usage();
            return;
        }
    };

    let mut mac: [u8; 128] = [0; 128];
    match in_fmt {

        ".s" => {

            if let Ok(_) = ctx.update(in_content.as_bytes()).unwrap().compute(&mut mac[..]) {
                printbytesln(&mac[..mac_len]);
            }

        },

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

            ctx.compute(&mut mac[..]).unwrap();
            printbytesln(&mac[..mac_len]);

        },

        _ => {
            println!("[!Err]: uninterpretable data-fomat.\n");
            println_subcmd_usage();
            return;
        }

    }

}

pub fn println_subcmd_usage() {
    println!("mac sub-command usage:");
    println!("    crypto mac [algorithm] [key (with suffix): \"{{string}}.s\" | \"{{filepath}}.f\" ] [in-data (with suffix): \"{{string}}.s\" | \"{{filepath}}.f\" ] ...");
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
    println!("and enter in-data as follows:");
    println!(" - if the input is the string \"abc\", enter \"abc.s\"");
    println!(" - if the input is the file \"efg.txt\", enter \"efg.txt.f\"");
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