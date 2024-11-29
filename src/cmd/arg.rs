use std::fs::File;
use std::io::Read;
use crate::cmd::BUF_INIT_CAP;
use crate::cmd::error::CommandError;
use crate::cmd::error::CommandErrorCode;

pub struct SuffixedArg;

pub enum ArgType {
    Hexadecimal,
    String,
    Filepath
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

    pub fn parse_arg(arg: &str) -> Result<(ArgType, &str), CommandError> {
        let n: usize = arg.len();
        if n < 2 {
            return Err(CommandError::new(CommandErrorCode::UninterpretableInputFormat));
        }
        let arg_type: ArgType = ArgType::from_suffix(&arg[(n - 2)..n])?;
        let arg_data: &str = &arg[..(n - 2)];
        return Ok((arg_type, arg_data));
    }

    pub fn to_bytes(arg: &str) -> Result<Vec<u8>, CommandError> {
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

    pub fn str_to_bytes(s: &str) -> Result<Vec<u8>, CommandError> {
        return Ok(s.as_bytes().to_vec());
    }

    pub fn hexdec_to_bytes(h: &str) -> Result<Vec<u8>, CommandError> {

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