use crate::crypto::rand::RandChaCha20;
use crate::cmd::printbytesln;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 {
        println_subcmd_usage();
        return;
    }

    // if args.len() < 2 {
    //     println!("[!Err]: rand sub-command takes at least 1 arguments.");
    //     println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto rand help\".");
    //     return;
    // }

    let Ok(len) = args[1].as_str().parse::<usize>() else {
        println!("[!Err]: length is not non-negative integer.");
        return;
    };

    let mut bytes: Vec<u8> = Vec::<u8>::with_capacity(len);
    unsafe { bytes.set_len(len); }
    RandChaCha20::new().unwrap().fill_bytes(&mut bytes).unwrap();
    printbytesln(&bytes[..]);

}

fn println_subcmd_usage() {
    println!("rand sub-command usage:");
    println!("    crypto rand [length] ...");
}