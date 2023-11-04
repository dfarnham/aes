use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use clap::Id;
use std::error::Error;
use std::io::{self, Write};

// Clap arg parser
mod argparse;

// AES algorithms
mod libaes;
use libaes::{aes_decrypt, aes_encrypt};

// Key Derivation Functions
mod kdf;
use kdf::Kdf;

// Utility functions
mod general;
use general::{get_ivector, get_passkey32, read_input_bytes, reset_sigpipe};

// Cipher type
#[derive(Debug, PartialEq)]
pub enum Cipher {
    ECB, // Electronic Codebook
    CBC, // Cipher Block Chaining
    CTR, // Integer Counter Mode
}

// Helper function: number of blocks for n-bytes
const fn blocks(n: usize) -> usize {
    match n % 16 == 0 {
        true => n / 16,
        false => n / 16 + 1, // padded block
    }
}

// ==============================================================

fn main() -> Result<(), Box<dyn Error>> {
    // Behave like a typical unix utility
    reset_sigpipe()?;
    let mut stdout = io::stdout().lock();

    // Parse command line arguments enforcing contraints with Clap, see src/argparse.rs
    let args = argparse::get_args();

    // Mode of operation.  This driver only tests encrypt
    let encrypt: bool = args.get_flag("encrypt");

    // Silences warnings regarding short or long passwords
    let quiet = args.get_flag("quiet");

    // Get the argument string containing bundled (bits-cipher) settings, e.g. --aes-256-cbc
    let ciph_desc = if let Some(s) = args.get_one::<Id>("aes128") {
        s.to_string()
    } else if let Some(s) = args.get_one::<Id>("aes192") {
        s.to_string()
    } else if let Some(s) = args.get_one::<Id>("aes256") {
        s.to_string()
    } else {
        "".to_string()
    };

    // Is a random initialization vector being created?
    let randiv: bool = args.get_flag("randiv");

    // Set the cipher mode (ecb, cbc, ctr)
    let cipher = if args.get_flag("ecb") || ciph_desc.contains("ecb") {
        Cipher::ECB
    } else if args.get_flag("cbc") || ciph_desc.contains("cbc") {
        Cipher::CBC
    } else if args.get_flag("ctr") || ciph_desc.contains("ctr") {
        Cipher::CTR
    } else if ciph_desc.is_empty() {
        return Err("missing cipher: --ecb,cbc,ctr or --aes-{128,192,256}-{ecb,cbc,ctr}".into());
    } else {
        unreachable!("argparse failed")
    };

    // Number of bits is specified with flags or will be derived from key length
    let bits_specified = if args.get_flag("128") || ciph_desc.contains("128") {
        Some(128)
    } else if args.get_flag("192") || ciph_desc.contains("192") {
        Some(192)
    } else if args.get_flag("256") || ciph_desc.contains("256") {
        Some(256)
    } else {
        None
    };

    // Set the Key Derivation Function to use
    let kdf = if args.get_flag("pbkdf2") {
        // PBKDF2 with minimum of 1,000 iterations (defaults to 10,000)
        let iter = 1_000.max(*args.get_one::<u32>("iter").expect("argparse default"));
        Some(Kdf::PBKDF2(iter))
    } else if args.get_flag("argon2") {
        Some(Kdf::ARGON2)
    } else {
        None
    };

    // This offset value is used in input/output/padding calculations
    let first_block_sz = if (kdf.is_some() || randiv) && cipher != Cipher::ECB {
        16
    } else {
        0
    };

    // Create a 32-byte passkey and set bit size to [128, 192, 256]
    let (bits, passkey) = get_passkey32(
        bits_specified,
        args.get_one::<String>("key"),
        args.get_one::<String>("hexkey"),
        quiet || kdf.is_some(),
    )?;

    // Read the input FILE as bytes and perform any Base-64/Hex decodings
    let bytes = read_input_bytes(
        args.get_one::<std::path::PathBuf>("FILE"),
        args.get_flag("ibase64"),
        args.get_flag("ihex"),
    )?;

    // That was fun
    if bytes.is_empty() {
        return Err("aes: empty input".into());
    }

    // Initialize the output byte buffer
    let mut output = vec![];

    // ============================================================================
    // Step 1 - Obtain the ivector and passkey, r/w block-1
    //
    // Note: iv resides in the 1st block when invoked with --randiv for [CBC, CTR],
    //       salt is the last 8 bytes of the 1st block when using --pbkdf2
    //       salt is the 1st block when using --argon2
    // ============================================================================
    let mut ivector = get_ivector(
        encrypt && (randiv || kdf.is_some()), // conditions for a random iv
        args.get_one::<String>("iv"),         // supplied iv
        quiet,                                // squelch warnings re short/truncated keys?
    )?;
    let (passkey, ivector) = match encrypt {
        true => match kdf {
            Some(ref hasher) => {
                match hasher {
                    Kdf::PBKDF2(_) => {
                        let salt: [u8; 8] = ivector[8..].try_into()?;
                        // Copy b"Salted__xxxxxxxx" to the 1st block of output
                        output.extend(b"Salted__");
                        output.extend(&salt);
                        hasher.keyiv(bits, &passkey, &salt)?
                    }
                    Kdf::ARGON2 => {
                        // Copy ivector to the 1st block of output
                        output.extend(&ivector);
                        hasher.keyiv(bits, &passkey, &ivector)?
                    }
                }
            }
            None => {
                // Copy the ivector to the 1st block of output
                if first_block_sz > 0 {
                    output.extend(&ivector);
                }
                (passkey, ivector)
            }
        },
        false => {
            // Read the iv (or salt for kdf's) from the 1st block of input
            if first_block_sz > 0 {
                ivector.copy_from_slice(&bytes[..16]);
            }
            match kdf {
                Some(ref hasher) => {
                    match hasher {
                        // ivector contains the salt, skip over b"Salted__"
                        Kdf::PBKDF2(_) => hasher.keyiv(bits, &passkey, &ivector[8..])?,
                        Kdf::ARGON2 => hasher.keyiv(bits, &passkey, &ivector)?,
                    }
                }
                None => (passkey, ivector),
            }
        }
    };

    // Option -P prints cipher details to stderr and returns
    if args.get_flag("P") {
        let block = match encrypt {
            true => output,
            false => bytes,
        };

        eprintln!("AES-{cipher:?}-{bits}");

        if let Some(ref hasher) = kdf {
            match hasher {
                Kdf::PBKDF2(_) => eprintln!("salt={}", hex::encode(&block[8..16]).to_uppercase()),
                Kdf::ARGON2 => eprintln!("salt={}", hex::encode(&block[..16]).to_uppercase()),
            }
        }

        match bits {
            128 => eprintln!("key={}", hex::encode(&passkey[0..16]).to_uppercase()),
            192 => eprintln!("key={}", hex::encode(&passkey[0..24]).to_uppercase()),
            _ => eprintln!("key={}", hex::encode(passkey).to_uppercase()),
        }

        eprintln!("iv ={}", hex::encode(ivector).to_uppercase());
        return Ok(());
    }

    // =================================================
    // Step 2 - Encrypt / Decrypt and handle final block
    // =================================================
    if encrypt {
        // Add encrypted bytes to output
        output.extend(aes_encrypt(bits, &passkey, &bytes, &cipher, &ivector));

        // Protect against output of a full pad block
        if args.get_flag("nopkcs") && cipher != Cipher::CTR {
            output.drain(16 * blocks(bytes.len() + first_block_sz)..);
        }
    } else {
        // Add decrypted bytes to output
        output.extend(aes_decrypt(bits, &passkey, &bytes[first_block_sz..], &cipher, &ivector));

        // Pad removal
        if cipher != Cipher::CTR {
            if args.get_flag("nopkcs") {
                output.drain((16 * blocks(bytes.len() - first_block_sz))..);
            } else {
                // The last byte value is the count of pad chars to remove
                let padcount = *output.last().ok_or("pad count error")? as usize;
                output.drain((16 * blocks(bytes.len() - first_block_sz) - padcount)..);
            }
        }
    }

    // =================================
    // Step 3 - Output as encoded or raw
    // =================================
    if args.get_flag("obase64") || args.get_flag("ohex") {
        let mut s = match args.get_flag("ohex") {
            true => hex::encode(output),
            false => general_purpose::STANDARD.encode(&output),
        };

        // Split Base-64 and Hex into 76 byte chunks
        while !s.is_empty() {
            let (chunk, rest) = s.split_at(std::cmp::min(76, s.len()));
            writeln!(stdout, "{chunk}")?;
            s = rest.into();
        }
    } else {
        stdout.write_all(&output)?;
    }

    Ok(())
}

// ============
//  NIST Tests
// ============
#[cfg(test)]
mod nist_tests;

// =============
// General Tests
// =============
#[cfg(test)]
mod tests;
