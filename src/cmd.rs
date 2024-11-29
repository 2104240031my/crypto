pub mod arg;
pub mod errror;
pub mod cmd_decrypt;
pub mod cmd_encrypt;
pub mod cmd_hash;
pub mod cmd_keyshare;
pub mod cmd_mac;
pub mod cmd_open;
pub mod cmd_pubkey;
pub mod cmd_seal;
pub mod cmd_sign;
pub mod cmd_verify;
pub mod cmd_xof;

const BUF_SIZE: usize = 65536;
const BUF_INIT_CAP: usize = 65536;

fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}