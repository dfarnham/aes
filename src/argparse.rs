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
        .arg(arg!(-e --encrypt "Encrypt"))
        .arg(arg!(-d --decrypt "Decrypt"))
        .group(ArgGroup::new("cryptmode").args(["encrypt", "decrypt"]).required(true))

        // Only one of
        .arg(arg!(-b --ecb "Cipher is Electronic Codebook").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(-c --cbc "Cipher is Cipher Block Chaining").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(-t --ctr "Cipher is Integer Counter Mode").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .group(ArgGroup::new("cipher").args(["ecb", "cbc", "ctr"]).required(false))

        // Only one of
        .arg(arg!(--"128").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(--"192").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .arg(arg!(--"256").conflicts_with_all(["aes128", "aes192", "aes256"]))
        .group(ArgGroup::new("bits").args(["128", "192", "256"]).required(false))

        // Only one of
        .arg(arg!(--"aes-128-ecb").conflicts_with_all(["aes192", "aes256"]))
        .arg(arg!(--"aes-128-cbc").conflicts_with_all(["aes192", "aes256"]))
        .arg(arg!(--"aes-128-ctr").conflicts_with_all(["aes192", "aes256"]))
        .group(
            ArgGroup::new("aes128")
                .args(["aes-128-ecb", "aes-128-cbc", "aes-128-ctr"])
                .required(false),
        )

        // Only one of
        .arg(arg!(--"aes-192-ecb").conflicts_with_all(["aes128", "aes256"]))
        .arg(arg!(--"aes-192-cbc").conflicts_with_all(["aes128", "aes256"]))
        .arg(arg!(--"aes-192-ctr").conflicts_with_all(["aes128", "aes256"]))
        .group(
            ArgGroup::new("aes192")
                .args(["aes-192-ecb", "aes-192-cbc", "aes-192-ctr"])
                .required(false),
        )

        // Only one of
        .arg(arg!(--"aes-256-ecb").conflicts_with_all(["aes128", "aes192"]))
        .arg(arg!(--"aes-256-cbc").conflicts_with_all(["aes128", "aes192"]))
        .arg(arg!(--"aes-256-ctr").conflicts_with_all(["aes128", "aes192"]))
        .group(
            ArgGroup::new("aes256")
                .args(["aes-256-ecb", "aes-256-cbc", "aes-256-ctr"])
                .required(false),
        )

        // Only one of, required
        .arg(arg!(-k --key <key> "16,24,32 byte passkey"))
        .arg(arg!(-K --hexkey <hexkey> "2-byte hex converted to 16,24,32 byte passkey"))
        .group(ArgGroup::new("passkey").args(["key", "hexkey"]).required(true))

        .arg(arg!(--iv <hexiv> "2-byte hex converted to 16 bytes").conflicts_with("randiv"))
        .arg(
            arg!(-r --randiv "Random iv output as first block on --encrypt, treat first block as iv on --decrypt")
                .conflicts_with_all(["iv", "hexiv"]),
        )

        .arg(arg!(-a --obase64 "Output as Base64").conflicts_with("ohex"))
        .arg(arg!(-A --ibase64 "Input is Base64").conflicts_with("ihex"))

        .arg(arg!(-x --ohex "Output as 2-byte hex").conflicts_with("obase64"))
        .arg(arg!(-X --ihex "Input is 2-byte hex").conflicts_with("ibase64"))

        .arg(arg!(--nopkcs "Prevents a full pad block being output on --encrypt, skip PKCS#7 pad removal on --decrypt"))

        .arg(arg!(p: -p "Print the iv/key"))
        .arg(arg!(P: -P "Print the iv/key and exit"))

        .arg(arg!(-q --quiet "Run quietly, no stderr warnings"))

        .arg(
            arg!(<FILE> "File to read, treats '-' as standard input")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        );

    app.get_matches_from(env::args().collect::<Vec<String>>())
}
