use crate::crypto::CryptoError;
use crate::crypto::Aead;
use crate::crypto::BlockCipher128;
use crate::crypto::aes::AesAlgorithm;
use crate::crypto::aes::Aes;
use crate::crypto::block_cipher_mode::BlockCipherMode128;
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
    } else if args.len() < 8 {
        println!("[!Err]: aead sub-command takes at least 7 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto aead help\".");
        return;
    }

    let seal: bool = match args[2].as_str() {
        "seal" => true,
        "open" => false,
        _         => {
            println!("[!Err]: invalid operation.");
            println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto aead help\".");
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

    let tmp: Result<(AeadState, usize, usize), CryptoError> = match args[1].as_str() {
        "aes-128-gcm"       => match Aes::new(AesAlgorithm::Aes128, &key[..]) {
            Ok(v)  => Ok((AeadState::AesGcm(v), 12, Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-192-gcm"       => match Aes::new(AesAlgorithm::Aes192, &key[..]) {
            Ok(v)  => Ok((AeadState::AesGcm(v), 12, Aes::BLOCK_SIZE)),
            Err(e) => Err(e)
        },
        "aes-256-gcm"       => match Aes::new(AesAlgorithm::Aes256, &key[..]) {
            Ok(v)  => Ok((AeadState::AesGcm(v), 12, Aes::BLOCK_SIZE)),
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

    let mut nonce: Vec<u8> = match SuffixedArg::to_bytes(args[4].as_str()) {
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

    let aad: Vec<u8> = match SuffixedArg::to_bytes(args[5].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let in_text: Vec<u8> = match SuffixedArg::to_bytes(args[6].as_str()) {
        Ok(v)  => v,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let mut out_text: Vec<u8> = Vec::<u8>::with_capacity(in_text.len() + if seal { tag_len } else { 0 });
    unsafe { out_text.set_len(in_text.len() - if !seal { tag_len } else { 0 }); }

    if seal {

        let mut tag: [u8; 16] = [0; 16];
        if let Err(e) = ctx.seal(&mut nonce, &aad, &in_text, &mut out_text, &mut tag[..]) {
            println!("{}", e);
            return;
        }

        for i in 0..16 {
            out_text.push(tag[i]);
        }

    } else {

        if in_text.len() < tag_len {
            println!("[!Err]: the ciphertext is too short.");
            return;
        }

        let tag: &[u8] = &in_text[(in_text.len() - tag_len)..];
        match ctx.open(&mut nonce, &aad, &in_text[..(in_text.len() - tag_len)], &mut out_text, &tag) {
            Ok(v)  => {
                if !v {
                    println!("[!Err]: verification failed.");
                    return;
                }
            },
            Err(_) => {
                println!("[!Err]: verification failed.");
                return;
            }
        }

    }

    let (out_fmt, out_src): (ArgType, &str) = match SuffixedArg::parse_arg(args[7].as_str()) {
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
    println!("aead sub-command usage:");
    println!("    crypto aead [algorithm] [operation] [key (with suffix)] [nonce (with suffix)] [aad (with suffix)] [in-text (with suffix)] [out-text (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - aes-128-gcm");
    println!(" - aes-192-gcm");
    println!(" - aes-256-gcm");
    println!(" - chacha20-poly1305");
    println!("");
    println!("the operations are listed below:");
    println!(" - seal");
    println!(" - open");
    println!("");
    println!("and enter key, nonce, aad, in-text, and out-text as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}

enum AeadState {
    AesGcm(Aes),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadState {

    fn seal(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::AesGcm(v)           => BlockCipherMode128::gcm_encrypt_and_generate(v, nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

    fn open(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::AesGcm(v)           => BlockCipherMode128::gcm_decrypt_and_verify(v, nonce, aad, ciphertext, plaintext, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
        };
    }

}