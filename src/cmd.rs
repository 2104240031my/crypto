pub mod cmd_hash;

pub fn println_cmd_usage() {
    println!("crypto command usage:");
    println!("    crypto [sub-command] ...");
    println!("");
    println!("available sub-commands are listed below:");
    println!(" - aead");
    println!(" - cipher");
    println!(" - hash");
    println!(" - help");
    println!(" - key-share");
    println!(" - mac");
    println!(" - sign");
    println!(" - verify");
}

pub fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}