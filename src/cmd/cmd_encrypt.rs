use crate::crypto::CryptoError;
use crate::crypto::BlockCipher;
use crate::crypto::StreamCipher;
use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ecb128;
use crate::crypto::block_cipher_mode::Cbc128;
use crate::crypto::block_cipher_mode::Cfb128Fb8;
use crate::crypto::block_cipher_mode::Cfb128Fb128;
use crate::crypto::block_cipher_mode::Ofb128;
use crate::crypto::block_cipher_mode::Ctr128;
use crate::crypto::chacha20::ChaCha20;
use crate::cmd::ArgType;
use crate::cmd::SuffixedArg;
use crate::cmd::printbytesln;
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

    let key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let tmp: Result<(CipherState, usize), CryptoError> = match args[1].as_str() {
        "aes-128-ecb"     => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128Ecb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-192-ecb"     => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192Ecb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-256-ecb"     => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256Ecb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-128-cbc"     => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128Cbc(v), Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cbc"     => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192Cbc(v), Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cbc"     => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256Cbc(v), Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-cfb-8"   => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128CfbFb8(v), Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cfb-8"   => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192CfbFb8(v), Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cfb-8"   => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256CfbFb8(v), Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-cfb-128" => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128CfbFb128(v), Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cfb-128" => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192CfbFb128(v), Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cfb-128" => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256CfbFb128(v), Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-ofb"     => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128Ofb(v), Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-ofb"     => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192Ofb(v), Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-ofb"     => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256Ofb(v), Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-ctr"     => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes128Ctr(v), Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-ctr"     => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes192Ctr(v), Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-ctr"     => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((CipherState::Aes256Ctr(v), Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "chacha20"        => match ChaCha20::new(&key[..], &[0; 16], 0) {
            Ok(v)  => Ok((CipherState::ChaCha20(v), 12)),
            Err(e) => Err(e)
        },
        _                 => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which cipher algorithms are supported, run \"crypto encrypt help\".");
            return;
        }
    };

    let (mut ctx, iv_len): (CipherState, usize) = match tmp {
        Ok(v)  => v,
        Err(_) => {
            println!("[!Err]: the length of key is too long or short.");
            return;
        }
    };

    let mut iv: Vec<u8> = match SuffixedArg::to_bytes(args[3].as_str()) {
        Ok(v)  => {
            if v.len() != iv_len {
                println!("[!Err]: the length of IV is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let plaintext: Vec<u8> = match SuffixedArg::to_bytes(args[4].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let mut ciphertext: Vec<u8> = Vec::<u8>::with_capacity(plaintext.len());
    unsafe { ciphertext.set_len(plaintext.len()); }

    ctx.encrypt(&mut iv, &plaintext, &mut ciphertext).unwrap();

    let (ciphertext_fmt, ciphertext_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[5].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    match ciphertext_fmt {
        ArgType::Hexadecimal => printbytesln(&ciphertext),
        ArgType::String      => println!("{}", match std::str::from_utf8(&ciphertext) {
            Ok(v)  => v,
            Err(_) => {
                println!("[!Err]: cannot convert to UTF-8.");
                return;
            }
        }),
        ArgType::Filepath    => {
            let tmp = File::create(ciphertext_src);
            if let Err(_) = tmp {
                println!("[!Err]: cannot open the file.");
                return;
            }
            if let Err(_) = tmp.unwrap().write_all(&ciphertext) {
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

enum CipherState {
    Aes128Ecb(Aes128),
    Aes192Ecb(Aes192),
    Aes256Ecb(Aes256),
    Aes128Cbc(Aes128),
    Aes192Cbc(Aes192),
    Aes256Cbc(Aes256),
    Aes128CfbFb8(Aes128),
    Aes192CfbFb8(Aes192),
    Aes256CfbFb8(Aes256),
    Aes128CfbFb128(Aes128),
    Aes192CfbFb128(Aes192),
    Aes256CfbFb128(Aes256),
    Aes128Ofb(Aes128),
    Aes192Ofb(Aes192),
    Aes256Ofb(Aes256),
    Aes128Ctr(Aes128),
    Aes192Ctr(Aes192),
    Aes256Ctr(Aes256),
    ChaCha20(ChaCha20),
}

impl CipherState {

    fn encrypt(&mut self, iv: &mut [u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes192Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes256Ecb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::Aes128Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes192Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes256Cbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::Aes128CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes192CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes256CfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes128CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes192CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes256CfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::Aes128Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes192Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes256Ofb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::Aes128Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::Aes192Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::Aes256Ctr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::ChaCha20(v)       => v.reset(iv, 1)?.encrypt_or_decrypt(plaintext, ciphertext),
        };
    }

}