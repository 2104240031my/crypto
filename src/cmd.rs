pub mod cmd_hash;
pub mod cmd_mac;

pub const BUFFER_SIZE: usize = 65536;

pub fn println_cmd_usage() {
    println!("crypto command usage:");
    println!("    crypto [sub-command] ...");
    println!("");
    println!("available sub-commands are listed below:");
    println!(" - aead");
    println!(" - cipher");
    println!(" - hash");
    println!(" - help");
    println!(" - key-gen");
    println!(" - key-share");
    println!(" - mac");
    println!(" - sign");
    println!(" - verify");
    println!(" - version");
}

pub fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}

// pub fn hexdecstr_to_bytes(hexdec: &str) -> Result<Vec<u8>, Error> {
//
//     let len: usize = hexdec.len();
//     if len & 1 == 1 {
//         // err
//     }
//
//     let vec: Vec<u8> = Vec<u8>::with_capacity(len >> 1);
//
// }