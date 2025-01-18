use crate::crypto::rand::Aes256Rng;
use crate::crypto::rand::ChaCha20Rng;
use crate::test::{
    DEBUG_PRINT_RAND,
    printbytesln
};

pub fn test_rand() -> usize {
    let mut err: usize = 0;
    err = err + test_aes_256_rng();
    err = err + test_chacha20_rng();
    return err;
}

pub fn test_aes_256_rng() -> usize {

    let mut rand: Aes256Rng = Aes256Rng::new().unwrap();
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

pub fn test_chacha20_rng() -> usize {

    let mut rand: ChaCha20Rng = ChaCha20Rng::new().unwrap();
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