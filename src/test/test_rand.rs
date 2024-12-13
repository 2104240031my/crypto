use crate::crypto::random::RandAes256;
use crate::crypto::random::RandChaCha20;
use crate::test::{
    DEBUG_PRINT_RAND,
    printbytesln
};

pub fn test_rand() -> usize {
    let mut err: usize = 0;
    err = err + test_randaes256();
    err = err + test_randchacha20();
    return err;
}

pub fn test_randaes256() -> usize {

    let mut rand: RandAes256 = RandAes256::new().unwrap();
    let mut buf: [u8; 32] = [0; 32];

    if DEBUG_PRINT_RAND {
        let n: usize = 16;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = 32;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = 9;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    if DEBUG_PRINT_RAND {
        let n: usize = 25;
        rand.fill_bytes(&mut buf[..n]).unwrap();
        printbytesln(&buf[..n]);
    }

    return 0;

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
        let n: usize = 128;
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