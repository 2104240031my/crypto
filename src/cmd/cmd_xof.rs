use crate::crypto::util::Xof;
use crate::crypto::util::XofAlgorithm;
use crate::cmd::arg::ArgType;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::BUF_SIZE;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;
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

    let algo: XofAlgorithm = match args[1].as_str() {
        "shake128" => XofAlgorithm::Shake128,
        "shake256" => XofAlgorithm::Shake256,
        _          => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which XOF algorithms are supported, run \"crypto xof help\".");
            return;
        }
    };

    let mut xof: Xof = Xof::new(algo);

    let Ok(d) = args[2].as_str().parse::<usize>() else {
        println!("[!Err]: output-length is not non-negative integer.");
        return;
    };

    let Ok((in_fmt, in_src)) = SuffixedArg::parse_arg(args[3].as_str()).map_err(printerrln) else { return; };

    let mut output: Vec<u8> = Vec::<u8>::with_capacity(d);
    unsafe { output.set_len(d); }
    match in_fmt {

        ArgType::Hexadecimal => {
            let msg: Vec<u8> = SuffixedArg::hexdec_to_bytes(in_src).unwrap();
            xof.update(&msg).unwrap();
        },

        ArgType::String      => {
            let msg: Vec<u8> = SuffixedArg::str_to_bytes(in_src).unwrap();
            xof.update(&msg).unwrap();
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
                        xof.update(&buf[..n]).unwrap();
                    }
                }
            }

        }

    }

    xof.output(&mut output[..], d).unwrap();
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