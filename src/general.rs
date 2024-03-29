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

// Read bytes from a file or stdin and decode from Base-64 or 2-byte Hex
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

    // Perform decodings (Base-64, 2-byte Hex)
    if b64 {
        // Keep only the Base-64 alphabet and decode
        bytes.retain(|&b| BASE64_ALPHABET.contains(char::from(b)));
        bytes = general_purpose::STANDARD
            .decode(bytes)
            .with_context(|| "base64::decode")?;
    } else if hex {
        // Keep only the Hex alphabet and decode
        bytes.retain(|&b| HEX_ALPHABET.contains(char::from(b)));
        bytes = hex::decode(bytes).with_context(|| "hex::decode")?;
    }

    Ok(bytes)
}

// 16-byte initialization vector (random, or bytes from 2-byte hex)
// Warn on short/long conversions
pub fn get_ivector(random: bool, iv: Option<&String>, quiet: bool) -> Result<[u8; 16], Box<dyn Error>> {
    let mut ivector = [0u8; 16];

    if let Some(hexiv) = iv {
        if !quiet && hexiv.len() < 32 {
            eprintln!("hex iv is too short, padding with zero bytes");
        } else if !quiet && hexiv.len() > 32 {
            eprintln!("hex iv is too long, ignoring excess");
        }
        let hexiv = match hexiv.len() % 2 {
            0 => hexiv.to_string(),
            _ => hexiv.to_owned() + "0",
        };
        let iv = hex::decode(hexiv).with_context(|| "hex::decode(hexiv)")?;
        let nbytes = 16.min(iv.len());
        ivector[..nbytes].copy_from_slice(&iv[..nbytes]);
    } else if random {
        ivector = rand::random();
    }

    Ok(ivector)
}

// Returns number of encryption bits and a 32-byte passkey
// Bits can be explicitly specified or will be derived from key length
// Key can be raw bytes, or converted from 2-byte hex
pub fn get_passkey32(
    bits: Option<usize>,
    key: Option<&String>,
    hexkey: Option<&String>,
    quiet: bool, // squelch warnings re short/truncated keys?
) -> Result<(usize, [u8; 32]), Box<dyn Error>> {
    let (keylen, key) = if let Some(key) = key {
        (key.len(), key.clone().into_bytes())
    } else if let Some(hexkey) = hexkey {
        if hexkey.len() % 2 == 0 {
            (
                hexkey.len() / 2,
                hex::decode(hexkey).with_context(|| "hex::decode(hexkey)")?,
            )
        } else {
            (
                hexkey.len() / 2 + 1,
                hex::decode(hexkey.to_owned() + "0").with_context(|| "hex::decode(hexkey)")?,
            )
        }
    } else {
        return Err("missing required: --key,hexkey (argparse failed)".into());
    };

    // Derive from the key length when bits is None
    let bits = match bits {
        Some(n) => n,
        None => match keylen {
            n if n <= 16 => 128,
            n if n > 16 && n <= 24 => 192,
            _ => 256,
        },
    };

    // Warn if bits doesn't align with key length
    if !quiet {
        if bits == 128 && keylen < 16 || bits == 192 && keylen < 24 || bits == 256 && keylen < 32 {
            eprintln!("{bits}-bit key is too short, padding with zero bytes");
        } else if bits == 128 && keylen > 16 || bits == 192 && keylen > 24 || bits == 256 && keylen > 32 {
            eprintln!("{bits}-bit key is too long, ignoring excess");
        }
    }

    // Copy key into a 32 byte passkey
    let mut passkey = [0u8; 32];
    let nbytes = 32.min(key.len().min(bits / 8));
    passkey[..nbytes].copy_from_slice(&key[..nbytes]);

    Ok((bits, passkey))
}
