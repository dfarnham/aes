use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use clap::Id;
use std::error::Error;
use std::io::{self, Write};

// clap arg parser
mod argparse;

mod libaes;
use libaes::{aes_decrypt, aes_encrypt};

mod general;
use general::{get_ivector, get_passkey, get_pbkdf2_keyiv, read_input_bytes, reset_sigpipe};

#[derive(Debug, PartialEq)]
pub enum Cipher {
    ECB,
    CBC,
    CTR,
}

// number of blocks for n-bytes
const fn blocks(n: usize) -> usize {
    match n % 16 == 0 {
        true => n / 16,
        false => n / 16 + 1, // padded block
    }
}

// print cipher details
fn print_keyiv(cipher: &Cipher, bits: usize, passkey: &[u8; 32], salt: &[u8], ivector: &[u8; 16], pbkdf2: bool) {
    eprintln!("AES-{cipher:?}-{bits}");
    if pbkdf2 {
        eprintln!("salt={}", hex::encode(salt).to_uppercase());
    }
    match bits {
        128 => eprintln!("key={}", hex::encode(&passkey[0..16]).to_uppercase()),
        192 => eprintln!("key={}", hex::encode(&passkey[0..24]).to_uppercase()),
        _ => eprintln!("key={}", hex::encode(passkey).to_uppercase()),
    }
    eprintln!("iv ={}", hex::encode(ivector).to_uppercase());
}

// ==============================================================

fn main() -> Result<(), Box<dyn Error>> {
    // behave like a typical unix utility
    reset_sigpipe()?;
    let mut stdout = io::stdout().lock();

    // parse command line arguments
    let args = argparse::get_args();

    // Password-Based Key Derivation Function-2 with minimum of 1,000 iterations
    let pbkdf2: bool = args.get_flag("pbkdf2");
    let iter = 1_000.max(*args.get_one::<u32>("iter").expect("argparse default"));

    // skips stderr warning messages if true
    let quiet = args.get_flag("quiet");

    // get the argument string for bundled option if present, e.g. --aes-256-cbc
    let ciph_desc = if let Some(s) = args.get_one::<Id>("aes128") {
        s.to_string()
    } else if let Some(s) = args.get_one::<Id>("aes192") {
        s.to_string()
    } else if let Some(s) = args.get_one::<Id>("aes256") {
        s.to_string()
    } else {
        "".to_string()
    };

    // set the cipher mode (ecb, cbc, ctr)
    let cipher = if args.get_flag("ecb") || ciph_desc.contains("ecb") {
        Cipher::ECB
    } else if args.get_flag("cbc") || ciph_desc.contains("cbc") {
        Cipher::CBC
    } else if args.get_flag("ctr") || ciph_desc.contains("ctr") {
        Cipher::CTR
    } else if ciph_desc.is_empty() {
        return Err("missing cipher: --ecb,cbc,ctr or --aes-{128,192,256}-{ecb,cbc,ctr}".into());
    } else {
        return Err("argparse failed".into());
    };

    // number of bits is specified or derived from key length in get_passkey()
    let bits_specified = if args.get_flag("128") || ciph_desc.contains("128") {
        Some(128)
    } else if args.get_flag("192") || ciph_desc.contains("192") {
        Some(192)
    } else if args.get_flag("256") || ciph_desc.contains("256") {
        Some(256)
    } else {
        None
    };

    // create the 32-byte passkey from the input key
    // bits is finalized as [128, 192, 256]
    let (bits, passkey) = get_passkey(
        bits_specified,
        args.get_one::<String>("key"),
        args.get_one::<String>("hexkey"),
        quiet || pbkdf2,
    )?;

    // set the 16-byte initialization vector to random or supplied value
    let randiv: bool = args.get_flag("randiv");
    let encrypt: bool = args.get_flag("encrypt");
    let mut ivector = get_ivector(
        encrypt && randiv, // conditions for a random iv
        args.get_one::<String>("iv"),
        quiet,
    )?;

    // iv will reside in the first block when invoked with --randiv for [CBC, CTR]
    // salt will reside in the last 8 bytes of first block when invoked with --pbkdf2 ( b"Salted__xxxxxxxx" )
    let randiv_sz = if (randiv || pbkdf2) && cipher != Cipher::ECB {
        16
    } else {
        0
    };

    // read the input as bytes
    let bytes = read_input_bytes(
        args.get_one::<std::path::PathBuf>("FILE"),
        args.get_flag("ibase64"),
        args.get_flag("ihex"),
    )?;

    if bytes.is_empty() {
        return Ok(());
    }

    // =====================
    //   Encrypt / Decrypt
    // =====================
    let mut output = vec![];
    if encrypt {
        // PBKDF2 (Password-Based Key Derivation Function 2)
        let passkey = match pbkdf2 {
            true => {
                let salt: [u8; 8] = rand::random();

                // copy b"Salted__xxxxxxxx" to the first block of output
                output = b"Salted__".to_vec();
                output.extend(&salt);

                let (key, iv) = get_pbkdf2_keyiv(bits, &passkey, &salt, iter)?;

                // set ivector, return key
                ivector = iv;
                key
            }
            false => passkey,
        };

        // copy the iv to the first block of output unless --pbkdf2
        if randiv_sz != 0 && !pbkdf2 {
            output = ivector.to_vec();
        }

        // print cipher details and return
        if args.get_flag("P") {
            let salt = if pbkdf2 { &output[8..16] } else { &[0u8; 0] };
            print_keyiv(&cipher, bits, &passkey, salt, &ivector, pbkdf2);
            return Ok(());
        }

        // add encrypted bytes to output
        output.extend(aes_encrypt(bits, &passkey, &bytes, &cipher, &ivector));

        // protect against output of a full pad block
        if args.get_flag("nopkcs") && cipher != Cipher::CTR {
            output.drain(16 * blocks(bytes.len() + randiv_sz)..);
        }
    } else {
        // read the iv (or salt if --pbkdf2) from the first block of input
        if randiv_sz != 0 {
            ivector.copy_from_slice(&bytes[..16]);
        }

        // PBKDF2 (Password-Based Key Derivation Function 2)
        let passkey = match pbkdf2 {
            true => {
                // ivector contains the salt, skip over b"Salted__"
                let salt = &ivector[8..];
                let (key, iv) = get_pbkdf2_keyiv(bits, &passkey, salt, iter)?;

                // set ivector, return key
                ivector = iv;
                key
            }
            false => passkey,
        };

        // print cipher details and return
        if args.get_flag("P") {
            let salt = if pbkdf2 { &bytes[8..16] } else { &[0u8; 0] };
            print_keyiv(&cipher, bits, &passkey, salt, &ivector, pbkdf2);
            return Ok(());
        }

        // add decrypted bytes to output
        output.extend(aes_decrypt(bits, &passkey, &bytes[randiv_sz..], &cipher, &ivector));

        if cipher != Cipher::CTR {
            if args.get_flag("nopkcs") {
                output.drain((16 * blocks(bytes.len() - randiv_sz))..);
            } else {
                // the last byte value is the count of pad chars to remove
                let padcount = *output.last().ok_or("pad count error")? as usize;
                output.drain((16 * blocks(bytes.len() - randiv_sz) - padcount)..);
            }
        }
    }

    // =================
    //     Output
    // =================
    if args.get_flag("obase64") || args.get_flag("ohex") {
        let mut s = match args.get_flag("ohex") {
            true => hex::encode(output),
            false => general_purpose::STANDARD.encode(&output),
        };

        // Base-64 and Hex split into 76 byte chunks
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
