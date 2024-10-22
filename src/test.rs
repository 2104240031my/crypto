mod test_aes;
mod test_ed25519;
mod test_hmac_sha2;
mod test_hmac_sha3;
mod test_sha2;
mod test_sha3;
mod test_x25519;

pub fn test() {
    test_aes::test_aes();
    test_sha2::test_sha2();
    test_sha3::test_sha3();
    test_x25519::test_x25519();
    test_ed25519::test_ed25519();
    test_hmac_sha2::test_hmac_sha2();
    test_hmac_sha3::test_hmac_sha3();
}

pub fn printbytesln(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}

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