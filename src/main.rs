mod cmd;
mod test;
#[allow(dead_code)]
mod crypto;

const VERSION: &str = "0.0.0";

fn main() {

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println_cmd_usage();
        return;
    }

    let cmd: fn (args: Vec<String>) = match args[1].as_str() {
        "aead"     => cmd::cmd_aead::cmd_main,
        "cipher"   => cmd::cmd_cipher::cmd_main,
        "hash"     => cmd::cmd_hash::cmd_main,
        "help"     => |_: Vec<String>| { println_cmd_usage(); },
        "keyshare" => cmd::cmd_keyshare::cmd_main,
        "mac"      => cmd::cmd_mac::cmd_main,
        "pubkey"   => cmd::cmd_pubkey::cmd_main,
        "sign"     => cmd::cmd_sign::cmd_main,
        "verify"   => cmd::cmd_verify::cmd_main,
        "version"  => |_: Vec<String>| { println!("crypto-v{}", VERSION) },
        #[cfg(debug_assertions)]
        "test"     => |_: Vec<String>| { test::test(); },
        _          => |_: Vec<String>| { println!("[!Err]: there is no such sub-command."); }
    };

    cmd((&args[1..]).to_vec());

}

fn println_cmd_usage() {
    println!("crypto command usage:");
    println!("    crypto [sub-command] ...");
    println!("");
    println!("available sub-commands are listed below:");
    println!(" - aead");
    println!(" - cipher");
    println!(" - hash");
    println!(" - help");
    println!(" - keyshare");
    println!(" - mac");
    println!(" - pubkey");
    println!(" - rand");
    println!(" - sign");
    println!(" - verify");
    println!(" - version");
}