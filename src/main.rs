use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use std::error::Error;
use std::io::{self, Write};

// clap arg parser
mod argparse;

mod libaes;
use libaes::{aes_decrypt, aes_encrypt};

mod general;
use general::{get_ivector, get_passkey, read_input_bytes, reset_sigpipe};

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

// ==============================================================

fn main() -> Result<(), Box<dyn Error>> {
    // behave like a typical unix utility
    reset_sigpipe()?;
    let mut stdout = io::stdout().lock();

    // parse command line arguments
    let args = argparse::get_args();

    // get the cipher mode (ecb, cbc, ctr)
    let cipher = if args.get_flag("ecb") {
        Cipher::ECB
    } else if args.get_flag("cbc") {
        Cipher::CBC
    } else if args.get_flag("ctr") {
        Cipher::CTR
    } else {
        return Err("missing required: --ecb,cbc,ctr (argparse group failed)".into());
    };

    // set the 16-byte initialization vector to random or supplied value
    let randiv: bool = args.get_flag("randiv");
    let encrypt: bool = args.get_flag("encrypt");
    let mut ivector = get_ivector(
        encrypt && randiv, // randiv and encrypt creates a random iv
        args.get_one::<String>("iv"),
        args.get_one::<String>("hexiv"),
    )?;

    // create the 32-byte passkey from the input key, bits is [128, 192, 256]
    let (bits, passkey) = get_passkey(args.get_one::<String>("key"), args.get_one::<String>("hexkey"))?;

    // read the input as bytes
    let bytes = read_input_bytes(
        args.get_one::<std::path::PathBuf>("FILE"),
        args.get_flag("ibase64"),
        args.get_flag("ihex"),
    )?;

    // iv will reside in the first block when invoked with --randiv for [CBC, CTR]
    let randiv_sz = if randiv && cipher != Cipher::ECB { 16 } else { 0 };

    // =====================
    //   Encrypt / Decrypt
    // =====================
    let mut output = vec![];
    if encrypt {
        // copy the iv to the first block of output
        if randiv_sz != 0 {
            output = ivector.to_vec();
        }

        // add encrypted bytes to output
        output.extend(aes_encrypt(bits, &passkey, &bytes, &cipher, &ivector));

        // protect against output of a full pad block
        if args.get_flag("nopkcs") && cipher != Cipher::CTR {
            output.drain(16 * blocks(bytes.len() + randiv_sz)..);
        }
    } else {
        // read the iv from the first block of input
        if randiv_sz != 0 {
            ivector.copy_from_slice(&bytes[..16]);
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
