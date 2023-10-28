use super::*;
use crate::libaes::{aes_decrypt, aes_encrypt};

mod vectors;
use crate::nist_tests::vectors::*;

#[test]
fn test_128_ecb_encrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB128_ENCRYPT.len()).step_by(3) {
        let key = hex::decode(ECB128_ENCRYPT[i])?;
        let input = hex::decode(ECB128_ENCRYPT[i + 1])?;
        let expected = hex::decode(ECB128_ENCRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32[..16].copy_from_slice(&key);

        let computed = aes_encrypt(128, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-ECB-128)\t{} {} {}",
            ECB128_ENCRYPT[i],
            ECB128_ENCRYPT[i + 1],
            ECB128_ENCRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_128_cbc_encrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC128_ENCRYPT.len()).step_by(4) {
        let key = hex::decode(CBC128_ENCRYPT[i])?;
        let input = hex::decode(CBC128_ENCRYPT[i + 1])?;
        let expected = hex::decode(CBC128_ENCRYPT[i + 2])?;
        let iv = hex::decode(CBC128_ENCRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32[..16].copy_from_slice(&key);

        let computed = aes_encrypt(128, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-CBC-128)\t{} {} {} {}",
            CBC128_ENCRYPT[i],
            CBC128_ENCRYPT[i + 1],
            CBC128_ENCRYPT[i + 2],
            CBC128_ENCRYPT[i + 3]
        );
    }
    Ok(())
}

#[test]
fn test_128_ecb_decrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB128_DECRYPT.len()).step_by(3) {
        let key = hex::decode(ECB128_DECRYPT[i])?;
        let input = hex::decode(ECB128_DECRYPT[i + 1])?;
        let expected = hex::decode(ECB128_DECRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32[..16].copy_from_slice(&key);

        let computed = aes_decrypt(128, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-ECB-128)\t{} {} {}",
            ECB128_DECRYPT[i],
            ECB128_DECRYPT[i + 1],
            ECB128_DECRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_128_cbc_decrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC128_DECRYPT.len()).step_by(4) {
        let key = hex::decode(CBC128_DECRYPT[i])?;
        let input = hex::decode(CBC128_DECRYPT[i + 1])?;
        let expected = hex::decode(CBC128_DECRYPT[i + 2])?;
        let iv = hex::decode(CBC128_DECRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32[..16].copy_from_slice(&key);

        let computed = aes_decrypt(128, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-CBC-128)\t{} {} {} {}",
            CBC128_DECRYPT[i],
            CBC128_DECRYPT[i + 1],
            CBC128_DECRYPT[i + 2],
            CBC128_DECRYPT[i + 3]
        );
    }
    Ok(())
}

#[test]
fn test_192_ecb_encrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB192_ENCRYPT.len()).step_by(3) {
        let key = hex::decode(ECB192_ENCRYPT[i])?;
        let input = hex::decode(ECB192_ENCRYPT[i + 1])?;
        let expected = hex::decode(ECB192_ENCRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32[..24].copy_from_slice(&key);

        let computed = aes_encrypt(192, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-ECB-192)\t{} {} {}",
            ECB192_ENCRYPT[i],
            ECB192_ENCRYPT[i + 1],
            ECB192_ENCRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_192_cbc_encrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC192_ENCRYPT.len()).step_by(4) {
        let key = hex::decode(CBC192_ENCRYPT[i])?;
        let input = hex::decode(CBC192_ENCRYPT[i + 1])?;
        let expected = hex::decode(CBC192_ENCRYPT[i + 2])?;
        let iv = hex::decode(CBC192_ENCRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32[..24].copy_from_slice(&key);

        let computed = aes_encrypt(192, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-CBC-192)\t{} {} {} {}",
            CBC192_ENCRYPT[i],
            CBC192_ENCRYPT[i + 1],
            CBC192_ENCRYPT[i + 2],
            CBC192_ENCRYPT[i + 3]
        );
    }
    Ok(())
}

#[test]
fn test_192_ecb_decrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB192_DECRYPT.len()).step_by(3) {
        let key = hex::decode(ECB192_DECRYPT[i])?;
        let input = hex::decode(ECB192_DECRYPT[i + 1])?;
        let expected = hex::decode(ECB192_DECRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32[..24].copy_from_slice(&key);

        let computed = aes_decrypt(192, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-ECB-192)\t{} {} {}",
            ECB192_DECRYPT[i],
            ECB192_DECRYPT[i + 1],
            ECB192_DECRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_192_cbc_decrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC192_DECRYPT.len()).step_by(4) {
        let key = hex::decode(CBC192_DECRYPT[i])?;
        let input = hex::decode(CBC192_DECRYPT[i + 1])?;
        let expected = hex::decode(CBC192_DECRYPT[i + 2])?;
        let iv = hex::decode(CBC192_DECRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32[..24].copy_from_slice(&key);

        let computed = aes_decrypt(192, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-CBC-192)\t{} {} {} {}",
            CBC192_DECRYPT[i],
            CBC192_DECRYPT[i + 1],
            CBC192_DECRYPT[i + 2],
            CBC192_DECRYPT[i + 3]
        );
    }
    Ok(())
}

#[test]
fn test_256_ecb_encrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB256_ENCRYPT.len()).step_by(3) {
        let key = hex::decode(ECB256_ENCRYPT[i])?;
        let input = hex::decode(ECB256_ENCRYPT[i + 1])?;
        let expected = hex::decode(ECB256_ENCRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32.copy_from_slice(&key);

        let computed = aes_encrypt(256, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-ECB-256)\t{} {} {}",
            ECB256_ENCRYPT[i],
            ECB256_ENCRYPT[i + 1],
            ECB256_ENCRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_256_cbc_encrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC256_ENCRYPT.len()).step_by(4) {
        let key = hex::decode(CBC256_ENCRYPT[i])?;
        let input = hex::decode(CBC256_ENCRYPT[i + 1])?;
        let expected = hex::decode(CBC256_ENCRYPT[i + 2])?;
        let iv = hex::decode(CBC256_ENCRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32.copy_from_slice(&key);

        let computed = aes_encrypt(256, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (E-CBC-256)\t{} {} {} {}",
            CBC256_ENCRYPT[i],
            CBC256_ENCRYPT[i + 1],
            CBC256_ENCRYPT[i + 2],
            CBC256_ENCRYPT[i + 3]
        );
    }
    Ok(())
}

#[test]
fn test_256_ecb_decrypt() -> Result<(), Box<dyn Error>> {
    let ivector: [u8; 16] = [0; 16];

    for i in (0..ECB256_DECRYPT.len()).step_by(3) {
        let key = hex::decode(ECB256_DECRYPT[i])?;
        let input = hex::decode(ECB256_DECRYPT[i + 1])?;
        let expected = hex::decode(ECB256_DECRYPT[i + 2])?;

        let mut key32: [u8; 32] = [0; 32];
        key32.copy_from_slice(&key);

        let computed = aes_decrypt(256, &key32, &input, &Cipher::ECB, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-ECB-256)\t{} {} {}",
            ECB256_DECRYPT[i],
            ECB256_DECRYPT[i + 1],
            ECB256_DECRYPT[i + 2]
        );
    }
    Ok(())
}

#[test]
fn test_256_cbc_decrypt() -> Result<(), Box<dyn Error>> {
    for i in (0..CBC256_DECRYPT.len()).step_by(4) {
        let key = hex::decode(CBC256_DECRYPT[i])?;
        let input = hex::decode(CBC256_DECRYPT[i + 1])?;
        let expected = hex::decode(CBC256_DECRYPT[i + 2])?;
        let iv = hex::decode(CBC256_DECRYPT[i + 3])?;

        let mut ivector: [u8; 16] = [0; 16];
        ivector.copy_from_slice(&iv);

        let mut key32: [u8; 32] = [0; 32];
        key32.copy_from_slice(&key);

        let computed = aes_decrypt(256, &key32, &input, &Cipher::CBC, &ivector);
        assert_eq!(expected, computed[..16]);

        println!(
            "PASSED (D-CBC-256)\t{} {} {} {}",
            CBC256_DECRYPT[i],
            CBC256_DECRYPT[i + 1],
            CBC256_DECRYPT[i + 2],
            CBC256_DECRYPT[i + 3]
        );
    }
    Ok(())
}
