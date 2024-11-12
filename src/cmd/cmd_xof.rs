use crate::crypto::CryptoError;
use crate::crypto::Xof;
use crate::crypto::sha3::Shake128;
use crate::crypto::sha3::Shake256;
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
        println!("[!Err]: xof sub-command takes at least 3 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto xof help\".");
        return;
    }

    let mut ctx: XofState = match args[1].as_str() {
        "shake128" => XofState::Shake128(Shake128::new()),
        "shake256" => XofState::Shake256(Shake256::new()),
        _          => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which XOF algorithms are supported, run \"crypto xof help\".");
            return;
        }
    };

    let d: usize = match args[2].as_str().parse::<usize>() {
        Ok(v)  => v,
        Err(_) => {
            println!("[!Err]: output-length is not non-negative integer.");
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

    let mut output: Vec<u8> = Vec::<u8>::with_capacity(d);
    unsafe { output.set_len(d); }
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

    ctx.output(&mut output[..], d).unwrap();
    printbytesln(&output[..]);

}

pub fn println_subcmd_usage() {
    println!("xof sub-command usage:");
    println!("    crypto xof [algorithm] [output-length (non-negative integer)] [message (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - shake128");
    println!(" - shake256");
    println!("");
    println!("and enter message as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}

enum XofState {
    Shake128(Shake128),
    Shake256(Shake256)
}

impl XofState {

    fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::Shake128(v) => v.update(msg).err(),
            Self::Shake256(v) => v.update(msg).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(self) };
    }

    fn output(&mut self, output: &mut [u8], d: usize) -> Result<(), CryptoError> {
        let err: Option<CryptoError> = match self {
            Self::Shake128(v) => v.output(output, d).err(),
            Self::Shake256(v) => v.output(output, d).err(),
        };
        return if let Some(e) = err { Err(e) } else { Ok(()) };
    }

}