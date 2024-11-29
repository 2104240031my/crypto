use crate::crypto::util::DiffieHellmanAlgorithm;
use crate::cmd::arg::SuffixedArg;
use crate::cmd::printbytesln;
use crate::cmd::printerrln;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 4 {
        println!("[!Err]: keyshare sub-command takes at least 3 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto keyshare help\".");
        return;
    }

    let algo: DiffieHellmanAlgorithm = match args[1].as_str() {
        "x25519"  => DiffieHellmanAlgorithm::X25519,
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which key-share algorithms are supported, run \"crypto keyshare help\".");
            return;
        }
    };

    let Ok(priv_key) = SuffixedArg::to_bytes(args[2].as_str()).map_err(printerrln) else { return; };
    if priv_key.len() != algo.priv_key_len() {
        println!("[!Err]: the length of private key is too long or short.");
        return;
    }

    let Ok(pub_key) = SuffixedArg::to_bytes(args[3].as_str()).map_err(printerrln) else { return; };
    if pub_key.len() != algo.pub_key_len() {
        println!("[!Err]: the length of public key is too long or short.");
        return;
    }

    let mut secret: [u8; 32] = [0; 32];
    algo.compute_shared_secret_oneshot(&priv_key, &pub_key, &mut secret[..algo.shared_secret_len()]).unwrap();
    printbytesln(&secret[..algo.shared_secret_len()]);

}

fn println_subcmd_usage() {
    println!("keyshare sub-command usage:");
    println!("    crypto keyshare [algorithm] [private-key (with suffix)] [public-key (with suffix)] ...");
    println!("");
    println!("supported algorithms are listed below:");
    println!(" - x25519");
    println!("");
    println!("and enter private-key and public-key as follows:");
    println!(" - if the data is the hexadecimal string \"00010203\", enter \"00010203.h\" (suffix is \".h\"))");
    println!(" - if the data is the string \"abc\", enter \"abc.s\" (suffix is \".s\"))");
    println!(" - if the data is the file \"efg.txt\", enter \"efg.txt.f\" (suffix is \".f\"))");
}