#[cfg(debug_assertions)]
mod test_aes;

#[cfg(debug_assertions)]
mod test_aes_mode;

#[cfg(debug_assertions)]
mod test_ed25519;

#[cfg(debug_assertions)]
mod test_hmac_sha2;

#[cfg(debug_assertions)]
mod test_hmac_sha3;

#[cfg(debug_assertions)]
mod test_sha2;

#[cfg(debug_assertions)]
mod test_sha3;

#[cfg(debug_assertions)]
mod test_x25519;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_ALL: bool       = false;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_AES: bool       = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_AES_MODE: bool  = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_ED25519: bool   = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_HMAC_SHA2: bool = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_HMAC_SHA3: bool = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_SHA2: bool      = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_SHA3: bool      = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub const DEBUG_PRINT_X25519: bool    = false | DEBUG_PRINT_ALL;

#[cfg(debug_assertions)]
pub fn test() {
    let mut err: usize = 0;
    err = err + print_test_result_msg(test_aes::test_aes(),             "AES module");
    err = err + print_test_result_msg(test_aes_mode::test_aes_mode(),   "Block Cipher Operation Modes for AES");
    err = err + print_test_result_msg(test_sha2::test_sha2(),           "SHA-2 module");
    err = err + print_test_result_msg(test_sha3::test_sha3(),           "SHA-3 module");
    err = err + print_test_result_msg(test_hmac_sha2::test_hmac_sha2(), "HMAC-SHA-2 module");
    err = err + print_test_result_msg(test_hmac_sha3::test_hmac_sha3(), "HMAC-SHA-3 module");
    err = err + print_test_result_msg(test_ed25519::test_ed25519(),     "Ed25519 module");
    err = err + print_test_result_msg(test_x25519::test_x25519(),       "X25519 module");
    if err == 0 {
        println!("[Ok]: no error occurred in total. All tests are passed.");
    } else {
        println!("[!Err]: {} errors occurred in total. Test is not passed.", err);
    }
}

#[cfg(debug_assertions)]
fn print_test_result_msg(err: usize, mod_name_text: &str) -> usize {
    if err == 0 {
        println!("[Ok]: no error occurred in testing {}.", mod_name_text);
    } else {
        println!("[!Err]: {} errors occurred in testing {}.", err, mod_name_text);
    }
    return err;
}

#[cfg(debug_assertions)]
pub fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}

#[cfg(debug_assertions)]
pub fn eqbytes(a: &[u8], b: &[u8]) -> bool {

    if a.len() != b.len() {
        return false;
    }

    let mut s: u8 = 0;

    for i in 0..a.len() {
        s = s | (a[i] ^ b[i]);
    }

    return s == 0;

}