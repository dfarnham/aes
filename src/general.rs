use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

const BASE64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_ALPHABET: &str = "ABCDEFabcdef0123456789";

// https://github.com/rust-lang/rust/issues/62569
pub fn reset_sigpipe() -> Result<(), Box<dyn Error>> {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal;

        unsafe {
            signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)?;
        }
    }
    Ok(())
}

// 16-byte initialization vector (random, bytes, or bytes from 2-byte hex)
pub fn get_ivector(random: bool, iv: Option<&String>, hexiv: Option<&String>) -> Result<[u8; 16], Box<dyn Error>> {
    let mut ivector = [0; 16];

    if random {
        ivector = rand::random();
    } else if let Some(iv) = iv {
        let nbytes = 16.min(iv.len());
        ivector[..nbytes].copy_from_slice(&iv.as_bytes()[..nbytes]);
    } else if let Some(hexiv) = hexiv {
        let iv = hex::decode(hexiv).with_context(|| "hex::decode(hexiv)")?;
        let nbytes = 16.min(iv.len());
        ivector[..nbytes].copy_from_slice(&iv[..nbytes]);
    }

    Ok(ivector)
}

// bits in input key (128, 192, 256)
// 32-byte passkey (bytes, or bytes from 2-byte hex)
pub fn get_passkey(key: Option<&String>, hexkey: Option<&String>) -> Result<(usize, [u8; 32]), Box<dyn Error>> {
    // get input key
    let key = if let Some(key) = key {
        key.clone().into_bytes()
    } else if let Some(hexkey) = hexkey {
        hex::decode(hexkey).with_context(|| "hex::decode(hexkey)")?
    } else {
        return Err("missing required: --key,hexkey (argparse failed)".into());
    };

    // number of bits in the input key [128, 192, 256]
    let bits = match key.len() {
        n if n <= 16 => 128,
        n if n > 16 && n <= 24 => 192,
        _ => 256,
    };

    // copy key into a 32 byte passkey
    let mut passkey: [u8; 32] = [0; 32];
    let nbytes = 32.min(key.len());
    passkey[..nbytes].copy_from_slice(&key[..nbytes]);

    Ok((bits, passkey))
}

// read bytes from a file or stdin and decoded from Base-64 or 2-byte Hex if requested
pub fn read_input_bytes(file: Option<&PathBuf>, b64: bool, hex: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = match file {
        Some(file) => file.clone(),
        _ => std::path::PathBuf::from("-"),
    };

    let mut bytes = vec![];
    let _input_name: String = match file.as_os_str() != "-" {
        true => {
            File::open(&file)
                .with_context(|| format!("could not open file `{:?}`", file.as_os_str()))?
                .read_to_end(&mut bytes)
                .with_context(|| format!("could not read file `{:?}`", file.as_os_str()))?;
            file.to_string_lossy().into()
        }
        false => {
            io::stdin()
                .read_to_end(&mut bytes)
                .with_context(|| "could not read `stdin`")?;
            "<stdin>".into()
        }
    };

    // perform byte conversions (Base-64, 2-byte Hex)
    if b64 {
        // keep only the Base-64 alphabet and decode
        bytes.retain(|&b| BASE64_ALPHABET.contains(char::from(b)));
        bytes = general_purpose::STANDARD
            .decode(bytes)
            .with_context(|| "base64::decode")?;
    } else if hex {
        // keep only the Hex alphabet and decode
        bytes.retain(|&b| HEX_ALPHABET.contains(char::from(b)));
        bytes = hex::decode(bytes).with_context(|| "hex::decode")?;
    }

    Ok(bytes)
}
