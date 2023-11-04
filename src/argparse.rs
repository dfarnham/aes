use clap::{
    arg, crate_description, crate_name, crate_version, value_parser, ArgGroup, ArgMatches, ColorChoice, Command,
};
use std::env;
use std::path::PathBuf;

#[rustfmt::skip]
pub fn get_args() -> ArgMatches {
    let app = Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .color(ColorChoice::Auto)
        .max_term_width(100)

        // Only one of, required
        .arg(arg!(-e --encrypt "Encrypt mode"))
        .arg(arg!(-d --decrypt "Decrypt mode"))
        .group(ArgGroup::new("cryptmode").args(["encrypt", "decrypt"]).required(true))

        // Only one of
        .arg(arg!(-b --ecb "Cipher is Electronic Codebook").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(-c --cbc "Cipher is Cipher Block Chaining").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(-t --ctr "Cipher is Integer Counter Mode").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .group(ArgGroup::new("cipher").args(["ecb", "cbc", "ctr"]).required(false))

        // Only one of
        .arg(arg!(--"128" "Key size" ).conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(--"192" "Key size").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(--"256" "Key size").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .group(ArgGroup::new("bits").args(["128", "192", "256"]).required(false))

        // Only one of
        .arg(arg!(--"aes-128-ecb" "Key size and cipher").conflicts_with_all(["aes192", "aes256"]))
        .arg(arg!(--"aes-128-cbc" "Key size and cipher").conflicts_with_all(["aes192", "aes256"]))
        .arg(arg!(--"aes-128-ctr" "Key size and cipher").conflicts_with_all(["aes192", "aes256"]))
        .group(
            ArgGroup::new("aes128")
                .args(["aes-128-ecb", "aes-128-cbc", "aes-128-ctr"])
                .required(false),
        )

        // Only one of
        .arg(arg!(--"aes-192-ecb" "Key size and cipher").conflicts_with_all(["aes128", "aes256"]))
        .arg(arg!(--"aes-192-cbc" "Key size and cipher").conflicts_with_all(["aes128", "aes256"]))
        .arg(arg!(--"aes-192-ctr" "Key size and cipher").conflicts_with_all(["aes128", "aes256"]))
        .group(
            ArgGroup::new("aes192")
                .args(["aes-192-ecb", "aes-192-cbc", "aes-192-ctr"])
                .required(false),
        )

        // Only one of
        .arg(arg!(--"aes-256-ecb" "Key size and cipher").conflicts_with_all(["aes128", "aes192"]))
        .arg(arg!(--"aes-256-cbc" "Key size and cipher").conflicts_with_all(["aes128", "aes192"]))
        .arg(arg!(--"aes-256-ctr" "Key size and cipher").conflicts_with_all(["aes128", "aes192"]))
        .group(
            ArgGroup::new("aes256")
                .args(["aes-256-ecb", "aes-256-cbc", "aes-256-ctr"])
                .required(false),
        )

        // Only one of, required
        .arg(arg!(-k --key <key> "Passphrase to create a passkey"))
        .arg(arg!(-K --hexkey <hexkey> "2-byte hex converted to 16,24,32 byte passkey"))
        .group(ArgGroup::new("passkey").args(["key", "hexkey"]).required(true))

        // Only one of
        .arg(arg!(--iv <hexiv> "2-byte hex converted to 16 byte iv").conflicts_with("randiv"))
        .arg(
            arg!(-r --randiv "Random iv output as 1st block on --encrypt, treat 1st block as iv on --decrypt")
                .conflicts_with("iv"),
        )

        // Only one of
        .arg(arg!(--pbkdf2 "Use password-based key derivation function 2 (PBKDF2)").conflicts_with("argon2"))
        .arg(arg!(--argon2 "Use password-based key derivation Argon2id").conflicts_with("pbkdf2"))

        // defaults to 10,000
        .arg(arg!(--iter <iter> "iterations for PBKDF2").value_parser(value_parser!(u32)).default_value("10000"))

        // Base-64
        .arg(arg!(-a --obase64 "Output as Base64").conflicts_with("ohex"))
        .arg(arg!(-A --ibase64 "Input is Base64").conflicts_with("ihex"))

        // Hex
        .arg(arg!(-x --ohex "Output as 2-byte hex").conflicts_with("obase64"))
        .arg(arg!(-X --ihex "Input is 2-byte hex").conflicts_with("ibase64"))

        // PKCS#7
        .arg(arg!(--nopkcs "Prevent a full pad block on --encrypt, skip PKCS#7 pad removal on --decrypt"))

        // Output cipher details to stderr
        .arg(arg!(P: -P "Print the salt/key/iv and exit"))

        // Supress stderr warnings
        .arg(arg!(-q --quiet "Silences warnings regarding short or long passwords"))

        // Input
        .arg(
            arg!(<FILE> "File to read, treats '-' as standard input")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        );

    app.get_matches_from(env::args().collect::<Vec<String>>())
}
