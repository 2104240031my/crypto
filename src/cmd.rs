pub mod cmd_aead;
pub mod cmd_cipher;
pub mod cmd_hash;
pub mod cmd_keyshare;
pub mod cmd_mac;
pub mod cmd_pubkey;
pub mod cmd_sign;
pub mod cmd_verify;

use std::clone::Clone;
use std::error::Error;
use std::fmt::Display;
use std::fs::File;
use std::marker::Copy;
use std::io::Read;

const BUF_SIZE: usize = 65536;
const BUF_INIT_CAP: usize = 65536;

struct SuffixedArg {}

enum ArgType {
    Hexadecimal,
    String,
    Filepath
}

fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}

impl ArgType {

    fn from_suffix(suffix: &str) -> Result<Self, CommandError> {
        return match suffix {
            ".h" => Ok(Self::Hexadecimal),
            ".s" => Ok(Self::String),
            ".f" => Ok(Self::Filepath),
            _    => Err(CommandError::new(CommandErrorCode::UninterpretableInputFormat))
        };
    }

}

impl SuffixedArg {

    fn parse_arg(arg: &str) -> Result<(ArgType, &str), CommandError> {
        let n: usize = arg.len();
        if n < 2 {
            return Err(CommandError::new(CommandErrorCode::UninterpretableInputFormat));
        }
        let arg_type: ArgType = ArgType::from_suffix(&arg[(n - 2)..n])?;
        let arg_data: &str = &arg[..(n - 2)];
        return Ok((arg_type, arg_data));
    }

    fn to_bytes(arg: &str) -> Result<Vec<u8>, CommandError> {
        let (arg_type, arg_data): (ArgType, &str,) = Self::parse_arg(arg)?;
        return match arg_type {
            // convert from hexadecimal string to bytes
            ArgType::Hexadecimal => Self::hexdec_to_bytes(arg_data),
            // convert string to bytes as is
            ArgType::String      => Self::str_to_bytes(arg_data),
            // get bytes from file
            ArgType::Filepath    => Self::file_content_to_bytes(arg_data)
        }
    }

    fn str_to_bytes(s: &str) -> Result<Vec<u8>, CommandError> {
        return Ok(s.as_bytes().to_vec());
    }

    fn hexdec_to_bytes(h: &str) -> Result<Vec<u8>, CommandError> {

        let mut vec: Vec<u8> = Vec::<u8>::with_capacity(BUF_INIT_CAP);

        let len: usize = h.len();
        if len & 1 == 1 {
            return Err(CommandError::new(CommandErrorCode::InvalidHexadecimalInputString));
        }

        for i in (0..len).step_by(2) {
            if let Ok(x) = u8::from_str_radix(&h[i..(i + 2)].to_string(), 16) {
                vec.push(x);
            } else {
                return Err(CommandError::new(CommandErrorCode::InvalidHexadecimalInputString));
            }
        }

        return Ok(vec);

    }

    fn file_content_to_bytes(f: &str) -> Result<Vec<u8>, CommandError> {

        let mut vec: Vec<u8> = Vec::<u8>::with_capacity(BUF_INIT_CAP);

        let fs = File::open(f);
        if let Err(_) = fs {
            return Err(CommandError::new(CommandErrorCode::CannotOpenFile));
        }

        return if let Err(_) = fs.unwrap().read_to_end(&mut vec) {
            Err(CommandError::new(CommandErrorCode::ErrorInFileReading))
        } else {
            Ok(vec)
        };

    }

}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CommandErrorCode {
    UninterpretableInputFormat,
    InvalidHexadecimalInputString,
    CannotOpenFile,
    ErrorInFileReading,
}

#[derive(Debug)]
pub struct CommandError {
    err_code: CommandErrorCode
}

impl CommandError {

    pub fn new(err_code: CommandErrorCode) -> Self {
        return Self{
            err_code: err_code,
        };
    }

}

impl Display for CommandError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "[!Err]: {}.", match &self.err_code {
            CommandErrorCode::UninterpretableInputFormat    => "uninterpretable data-fomat",
            CommandErrorCode::InvalidHexadecimalInputString => "invalid hexadecimal string",
            CommandErrorCode::CannotOpenFile                => "cannot open the file",
            CommandErrorCode::ErrorInFileReading            => "an error occurred while reading the file",
        });
    }

}

impl Error for CommandError {}