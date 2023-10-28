use clap::{
    arg, crate_description, crate_name, crate_version, value_parser, ArgGroup, ArgMatches, ColorChoice, Command,
};
use std::env;
use std::path::PathBuf;

pub fn get_args() -> ArgMatches {
    let app = Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .color(ColorChoice::Auto)
        .max_term_width(100)

        .arg(arg!(-e --encrypt "Encrypt"))
        .arg(arg!(-d --decrypt "Decrypt"))
        .group(ArgGroup::new("cryptmode")
             .args(["encrypt", "decrypt"])
             .required(true))

        .arg(arg!(-b --ecb "Cipher is Electronic Codebook"))
        .arg(arg!(-c --cbc "Cipher is Cipher Block Chaining"))
        .arg(arg!(-t --ctr "Cipher is Integer Counter Mode"))
        .group(ArgGroup::new("cipher")
             .args(["ecb", "cbc", "ctr"])
             .required(true))

        .arg(arg!(-A --ibase64 "Input is Base64").conflicts_with("ihex"))
        .arg(arg!(-a --obase64 "Output as Base64").conflicts_with("ohex"))

        .arg(arg!(-X --ihex "Input is 2-byte hex").conflicts_with("ibase64"))
        .arg(arg!(-x --ohex "Output as 2-byte hex").conflicts_with("obase64"))

        .arg(arg!(--nopkcs "Prevents a full pad block being output on --encrypt, skip PKCS#7 pad removal on --decrypt"))

        .arg(arg!(-r --randiv "Random \"iv\" output as first block on --encrypt, treat first block as \"iv\" on --decrypt").conflicts_with_all(["iv", "hexiv"]))
        .arg(arg!(--iv <iv> "16 byte initialization vector").conflicts_with_all(["randiv", "hexiv"]))
        .arg(arg!(--hexiv <hexiv> "2-byte hex converted to 16 bytes").conflicts_with_all(["randiv", "iv"]))

        .arg(arg!(-k --key <key> "16,24,32 byte passkey"))
        .arg(arg!(-K --hexkey <hexkey> "2-byte hex converted to 16,24,32 byte passkey"))
        .group(ArgGroup::new("passkey")
             .args(["key", "hexkey"])
             .required(true))

        .arg(arg!(<FILE> "File to read, treats '-' as standard input").required(false).value_parser(value_parser!(PathBuf)));

    app.get_matches_from(env::args().collect::<Vec<String>>())
}
