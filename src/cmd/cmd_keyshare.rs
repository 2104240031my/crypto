use crate::crypto::CryptoError;
use crate::crypto::DiffieHellman;
use crate::crypto::x25519::X25519;
use crate::cmd::SuffixedArg;
use crate::cmd::printbytesln;

pub fn cmd_main(args: Vec<String>) {

    if args.len() == 1 || (args.len() == 2 && args[1] == "help") {
        println_subcmd_usage();
        return;
    } else if args.len() < 4 {
        println!("[!Err]: keyshare sub-command takes at least 3 arguments.");
        println!("[Info]: if you want to know the syntax of the sub-command, run \"crypto keyshare help\".");
        return;
    }

    let (keyshare, priv_key_len, pub_key_len, secret_len): (
        fn (k: &[u8], a: &[u8], v: &mut [u8]) -> Result<(), CryptoError>,
        usize,
        usize,
        usize
    ) = match args[1].as_str() {
        "x25519"  => (X25519::compute_shared_secret, X25519::PRIVATE_KEY_LEN, X25519::PUBLIC_KEY_LEN, X25519::SHARED_SECRET_LEN),
        _         => {
            println!("[!Err]: unsupported algorithm.");
            println!("[Info]: if you want to know which key-share algorithms are supported, run \"crypto keyshare help\".");
            return;
        }
    };

    let priv_key: Vec<u8> = match SuffixedArg::to_bytes(args[2].as_str()) {
        Ok(v)  => {
            if v.len() != priv_key_len {
                println!("[!Err]: the length of private key is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let pub_key: Vec<u8> = match SuffixedArg::to_bytes(args[3].as_str()) {
        Ok(v)  => {
            if v.len() != pub_key_len {
                println!("[!Err]: the length of public key is too long or short.");
                return;
            }
            v
        },
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mut secret: [u8; 32] = [0; 32];
    keyshare(&priv_key, &pub_key, &mut secret[..secret_len]).unwrap();
    printbytesln(&secret[..secret_len]);

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