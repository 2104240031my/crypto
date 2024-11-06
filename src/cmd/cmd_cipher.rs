use crate::crypto::CryptoError;
use crate::crypto::BlockCipher128;
use crate::crypto::aes::AesAlgorithm;
use crate::crypto::aes::Aes;
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
    } else if args.len() < 7 {
        println!("[!Err]: cipher sub-command takes at least 6 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto cipher help\".");
        return;
    }

    let enc: bool = match args[2].as_str() {
        "encrypt" => true,
        "decrypt" => false,
        _         => {
            println!("[!Err]: invalid operation.");
            println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto cipher help\".");
            return;
        }
    };

    let key: Vec<u8> = match SuffixedArg::to_bytes(args[3].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let tmp: Result<(CipherState, usize), CryptoError> = match args[1].as_str() {
        "aes-128-ecb"     => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesEcb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-192-ecb"     => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesEcb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-256-ecb"     => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesEcb(v), 0)),
            Err(e) => Err(e)
        },
        "aes-128-cbc"     => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCbc(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cbc"     => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCbc(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cbc"     => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCbc(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-cfb-8"   => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb8(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cfb-8"   => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb8(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cfb-8"   => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb8(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-cfb-128" => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb128(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-cfb-128" => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb128(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-cfb-128" => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCfbFb128(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-ofb"     => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesOfb(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-ofb"     => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesOfb(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-ofb"     => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesOfb(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-ctr"     => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCtr(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-ctr"     => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCtr(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-ctr"     => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((CipherState::AesCtr(v), Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "chacha20"        => match ChaCha20::new(&key[..]) {
            Ok(v)  => Ok((CipherState::ChaCha20(v), 12)),
            Err(e) => Err(e)
        },
        _                 => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which cipher algorithms are supported, run \"crypto cipher help\".");
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

    let mut iv: Vec<u8> = match SuffixedArg::to_bytes(args[4].as_str()) {
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

    let in_text: Vec<u8> = match SuffixedArg::to_bytes(args[5].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let mut out_text: Vec<u8> = Vec::<u8>::with_capacity(in_text.len());
    unsafe { out_text.set_len(in_text.len()); }

    if let Err(e) = if enc {
        ctx.encrypt(&mut iv, &in_text, &mut out_text)
    } else {
        ctx.decrypt(&mut iv, &in_text, &mut out_text)
    } {
        println!("[!Err]: {}.", e);
        return;
    }

    let (out_fmt, out_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[6].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    match out_fmt {
        ArgType::Hexadecimal => printbytesln(&out_text),
        ArgType::String      => println!("{}", match std::str::from_utf8(&out_text) {
            Ok(v)  => v,
            Err(_) => {
                println!("[!Err]: cannot convert to UTF-8.");
                return;
            }
        }),
        ArgType::Filepath    => {
            let tmp = File::create(out_src);
            if let Err(_) = tmp {
                println!("[!Err]: cannot open the file.");
                return;
            }
            if let Err(_) = tmp.unwrap().write_all(&out_text) {
                println!("[!Err]: an error occurred while writing data to file.");
                return;
            }
        }
    }

}

pub fn println_subcmd_usage() {
    println!("cipher sub-command usage:");
    println!("    crypto cipher [algorithm] [operation] [key (with suffix)] [iv (or icb, nonce, etc.) (with suffix)] [in-text (with suffix)] [out-text (with suffix)] ...");
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
    println!("the operations are listed below:");
    println!(" - encrypt");
    println!(" - decrypt");
    println!("");
    println!("and enter key, iv, in-text, and out-text as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}

enum CipherState {
    AesEcb(Aes),
    AesCbc(Aes),
    AesCfbFb8(Aes),
    AesCfbFb128(Aes),
    AesOfb(Aes),
    AesCtr(Aes),
    ChaCha20(ChaCha20),
}

impl CipherState {

    fn encrypt(&mut self, iv: &mut [u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::AesEcb(v)      => BlockCipherMode128::ecb_encrypt_blocks(v, plaintext, ciphertext),
            Self::AesCbc(v)      => BlockCipherMode128::cbc_encrypt_blocks(v, iv, plaintext, ciphertext),
            Self::AesCfbFb8(v)   => BlockCipherMode128::cfb_fb8_encrypt(v, iv, plaintext, ciphertext),
            Self::AesCfbFb128(v) => BlockCipherMode128::cfb_fb128_encrypt(v, iv, plaintext, ciphertext),
            Self::AesOfb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, plaintext, ciphertext),
            Self::AesCtr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, plaintext, ciphertext),
            Self::ChaCha20(v)    => v.encrypt_or_decrypt_with_counter(iv, 1, plaintext, ciphertext),
        };
    }

    fn decrypt(&mut self, iv: &mut [u8], ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::AesEcb(v)      => BlockCipherMode128::ecb_decrypt_blocks(v, ciphertext, plaintext),
            Self::AesCbc(v)      => BlockCipherMode128::cbc_decrypt_blocks(v, iv, ciphertext, plaintext),
            Self::AesCfbFb8(v)   => BlockCipherMode128::cfb_fb8_decrypt(v, iv, ciphertext, plaintext),
            Self::AesCfbFb128(v) => BlockCipherMode128::cfb_fb128_decrypt(v, iv, ciphertext, plaintext),
            Self::AesOfb(v)      => BlockCipherMode128::ofb_encrypt_or_decrypt(v, iv, ciphertext, plaintext),
            Self::AesCtr(v)      => BlockCipherMode128::ctr_encrypt_or_decrypt(v, iv, 16, ciphertext, plaintext),
            Self::ChaCha20(v)    => v.encrypt_or_decrypt_with_counter(iv, 1, ciphertext, plaintext),
        };
    }

}