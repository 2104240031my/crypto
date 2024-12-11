use crate::crypto::rand::RandChaCha20;
use crate::test::{
    DEBUG_PRINT_RAND,
    printbytesln
};

pub fn test_rand() -> usize {
    let mut err: usize = 0;
    err = err + test_randchacha20();
    return err;
}

pub fn test_randchacha20() -> usize {

    let mut rand: RandChaCha20 = RandChaCha20::new().unwrap();
    let mut buf: [u8; 128] = [0; 128];

    if DEBUG_PRINT_RAND {
        let n: usize = 64;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = buf.len();
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = 39;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = 101;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    return 0;

}