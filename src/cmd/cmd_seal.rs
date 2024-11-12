use crate::crypto::CryptoError;
use crate::crypto::Aead;
use crate::crypto::BlockCipher;
use crate::crypto::aes::Aes128;
use crate::crypto::aes::Aes192;
use crate::crypto::aes::Aes256;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
use crate::crypto::block_cipher_mode::Ccm128;
use crate::crypto::block_cipher_mode::Gcm128;
use crate::crypto::chacha20_poly1305::ChaCha20Poly1305;
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
        println!("[!Err]: seal sub-command takes at least 6 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto seal help\".");
        return;
    }

    let key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let tmp: Result<(AeadState, usize, usize), CryptoError> = match args[1].as_str() {
        "aes-128-ccm"       => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes128Ccm(v), 12, Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-ccm"       => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes192Ccm(v), 12, Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-ccm"       => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes256Ccm(v), 12, Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-128-gcm"       => match Aes128::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes128Gcm(v), 12, Aes128::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-gcm"       => match Aes192::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes192Gcm(v), 12, Aes192::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-gcm"       => match Aes256::new(&key[..]) {
            Ok(v)  => Ok((AeadState::Aes256Gcm(v), 12, Aes256::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "chacha20-poly1305" => match ChaCha20Poly1305::new(&key[..]) {
            Ok(v)  => Ok((AeadState::ChaCha20Poly1305(v), ChaCha20Poly1305::NONCE_LEN, ChaCha20Poly1305::TAG_LEN)),
            Err(e) => Err(e)
        },
        _             => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which aead algorithms are supported, run \"crypto aead help\".");
            return;
        }
    };

    let (mut ctx, nonce_len, tag_len): (AeadState, usize, usize) = match tmp {
        Ok(v)  => v,
        Err(_) => {
            println!("[!Err]: the length of key is too long or short.");
            return;
        }
    };

    let mut nonce: Vec<u8> = match SuffixedArg::to_bytes(args[3].as_str()) {
        Ok(v)  => {
            if v.len() != nonce_len {
                println!("[!Err]: the length of nonce is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let aad: Vec<u8> = match SuffixedArg::to_bytes(args[4].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let plaintext: Vec<u8> = match SuffixedArg::to_bytes(args[5].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let mut ciphertext: Vec<u8> = Vec::<u8>::with_capacity(plaintext.len() + tag_len);
    unsafe { ciphertext.set_len(plaintext.len()); }

    let mut tag: [u8; 16] = [0; 16];
    if let Err(e) = ctx.seal(&mut nonce, &aad, &plaintext, &mut ciphertext, &mut tag[..]) {
        println!("{}", e);
        return;
    }
    for i in 0..16 {
        ciphertext.push(tag[i]);
    }

    let (ciphertext_fmt, ciphertext_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[6].as_str()) {
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

enum AeadState {
    Aes128Ccm(Aes128),
    Aes192Ccm(Aes192),
    Aes256Ccm(Aes256),
    Aes128Gcm(Aes128),
    Aes192Gcm(Aes192),
    Aes256Gcm(Aes256),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadState {

    fn seal(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Ccm(v)        => BlockCipherMode128::ccm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes128Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes192Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Gcm(v)        => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

}