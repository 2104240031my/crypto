pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {

    if a.len() != b.len() {
        return false;
    }

    let mut s: u8 = 0;

    for i in 0..a.len() {
        s = s | (a[i] ^ b[i]);
    }

    return s == 0;

}