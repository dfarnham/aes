use super::*;
use crate::general::{get_ivector, get_passkey, get_pbkdf2_keyiv};
use crate::libaes::aes_decrypt;
use crate::Cipher;
use hex_literal::hex;

#[test]
fn test_pbkdf2() -> Result<(), Box<dyn Error>> {
    // 128
    let (key, iv) = get_pbkdf2_keyiv(128, b"Password", b"NaCl", 80_000)?;
    assert_eq!(&key[..16], hex!("4ddcd8f60b98be21830cee5ef22701f9"));
    assert_eq!(iv, hex!("641a4418d04c0414aeff08876b34ab56"));

    // 192
    let (key, iv) = get_pbkdf2_keyiv(192, b"Password", b"NaCl", 80_000)?;
    assert_eq!(&key[..24], hex!("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414"));
    assert_eq!(iv, hex!("aeff08876b34ab56a1d425a122583354"));

    // 256
    let (key, iv) = get_pbkdf2_keyiv(256, b"Password", b"NaCl", 80_000)?;
    assert_eq!(
        key,
        hex!("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56")
    );
    assert_eq!(iv, hex!("a1d425a1225833549adb841b51c9b317"));

    Ok(())
}

#[test]
fn test_get_ivector() -> Result<(), Box<dyn Error>> {
    let ivector = get_ivector(false, None, false)?;
    assert_eq!(ivector, hex!("00000000000000000000000000000000"));

    let ivector = get_ivector(false, Some(&String::from("a")), false)?;
    assert_eq!(ivector, hex!("a0000000000000000000000000000000"));

    let ivector = get_ivector(false, Some(&String::from("0a")), false)?;
    assert_eq!(ivector, hex!("0a000000000000000000000000000000"));

    let ivector = get_ivector(false, Some(&String::from("ABCDEF")), false)?;
    assert_eq!(ivector, hex!("abcdef00000000000000000000000000"));

    let ivector = get_ivector(false, Some(&String::from("abcdef00000000000000000000ABCDEF")), false)?;
    assert_eq!(ivector, hex!("abcdef00000000000000000000abcdef"));

    Ok(())
}

#[test]
#[should_panic]
fn test_get_ivector_panic() {
    get_ivector(false, Some(&String::from("xyz")), false).unwrap();
}

#[test]
fn test_get_passkey() -> Result<(), Box<dyn Error>> {
    let quiet = true;

    // pub fn get_passkey(
    //     bits: Option<usize>,
    //     key: Option<&String>,
    //     hexkey: Option<&String>,
    //     quiet: bool) > Result<(usize, [u8; 32]), Box<dyn Error>> { ... }

    // 128 - derived
    let hexkey = "abcdef".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 128 && hexkey.len() < 32);
    assert_eq!(
        passkey,
        hex!("abcdef0000000000000000000000000000000000000000000000000000000000")
    );

    let hexkey = "abcdef0123456789ABCDEF0123456789".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 128 && hexkey.len() == 32);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789ABCDEF012345678900000000000000000000000000000000")
    );

    // 192 - derived
    let hexkey = "abcdef0123456789ABCDEF0123456789a".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 192 && hexkey.len() > 32 && hexkey.len() <= 48);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789ABCDEF0123456789A0000000000000000000000000000000")
    );

    let hexkey = "abcdef0123456789abcdef0123456789ABCdef0123456789".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 192 && hexkey.len() == 48);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789ABCDEF0123456789abcdef01234567890000000000000000")
    );

    // 256 - derived
    let hexkey = "abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 256 && hexkey.len() == 64);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789")
    );

    let hexkey = "abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789ab".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), quiet)?;
    assert!(bits == 256 && hexkey.len() > 64);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789")
    );

    // 128 - explicit
    let hexkey = "abcdef".to_string();
    let (bits, passkey) = get_passkey(Some(128), None, Some(&hexkey), quiet)?;
    assert!(bits == 128 && hexkey.len() < 32);
    assert_eq!(
        passkey,
        hex!("ABCDEF0000000000000000000000000000000000000000000000000000000000")
    );

    let hexkey = "abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789".to_string();
    let (bits, passkey) = get_passkey(Some(128), None, Some(&hexkey), quiet)?;
    assert!(bits == 128 && hexkey.len() > 32);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789abcdef012345678900000000000000000000000000000000")
    );

    // 192 - explicit
    let hexkey = "abcdef0123456789ABCDEF0123456789abcd".to_string();
    let (bits, passkey) = get_passkey(Some(192), None, Some(&hexkey), quiet)?;
    assert!(bits == 192 && hexkey.len() < 48);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789abcdef0123456789ABCD0000000000000000000000000000")
    );

    let hexkey = "abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789".to_string();
    let (bits, passkey) = get_passkey(Some(192), None, Some(&hexkey), quiet)?;
    assert!(bits == 192 && hexkey.len() > 48);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789abcdef0123456789ABCDEF01234567890000000000000000")
    );

    // 256 - explicit
    let hexkey = "abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789".to_string();
    let (bits, passkey) = get_passkey(Some(256), None, Some(&hexkey), quiet)?;
    assert!(bits == 256 && hexkey.len() == 64);
    assert_eq!(
        passkey,
        hex!("ABCDEF0123456789abcdef0123456789ABCDEF0123456789ABCDEF0123456789")
    );

    // 128 - derived - ascii key
    let key = "R&D".to_string();
    let (bits, passkey) = get_passkey(None, Some(&key), None, quiet)?;
    assert!(bits == 128);
    assert_eq!(
        passkey,
        hex!("5226440000000000000000000000000000000000000000000000000000000000")
    );

    let key = "Allman Brothers!".to_string();
    let (bits, passkey) = get_passkey(None, Some(&key), None, quiet)?;
    assert!(bits == 128);
    assert_eq!(
        passkey,
        hex!("416C6C6D616E2042726F74686572732100000000000000000000000000000000")
    );
    Ok(())
}

#[test]
fn test_cryptopals() -> Result<(), Box<dyn Error>> {
    let expected = b"I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
";
    let b64_encoded = true;
    let msg = read_input_bytes(Some(&std::path::PathBuf::from("src/tests/cp7.txt")), b64_encoded, false)?;
    let hexkey = "59454c4c4f57205355424d4152494e45".to_string();
    let (bits, passkey) = get_passkey(None, None, Some(&hexkey), true)?;
    let out = aes_decrypt(bits, &passkey, &msg, &Cipher::ECB, &[0u8; 16]);
    // aes_decrypt() doesn't perform pad char removal, so test up to the length of expected
    assert_eq!(out[..(expected.len())].to_vec(), expected);
    Ok(())
}
