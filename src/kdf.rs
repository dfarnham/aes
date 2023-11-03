use argon2::Argon2;
use pbkdf2::pbkdf2_hmac_array;
use std::error::Error;

// Password-Based Key Derivation Functions
//
// Stretches an input password and returns a TUPLE (32-byte password, 16-byte initialization vector)
#[derive(Clone, Debug)]
pub enum Kdf {
    PBKDF2(u32), // https://en.wikipedia.org/wiki/PBKDF2
    ARGON2,      // https://en.wikipedia.org/wiki/Argon2
}
impl Kdf {
    pub fn keyiv(&self, bits: usize, password: &[u8], salt: &[u8]) -> Result<([u8; 32], [u8; 16]), Box<dyn Error>> {
        match self {
            Self::PBKDF2(iter) => Self::kiv(bits, &pbkdf2_hmac_array::<sha2::Sha256, 48>(password, salt, *iter)),
            Self::ARGON2 => {
                let mut key = [0u8; 48];
                Argon2::default()
                    .hash_password_into(password, salt, &mut key)
                    .map_err(|e| format!("Argon2: {e}"))?;
                Self::kiv(bits, &key)
            }
        }
    }

    // Extract a key/iv pair from a stretched key for bit sizes [128, 192, 256]
    fn kiv(bits: usize, key: &[u8; 48]) -> Result<([u8; 32], [u8; 16]), Box<dyn Error>> {
        Ok(match bits {
            128 => (key[..32].try_into()?, key[16..32].try_into()?),
            192 => (key[..32].try_into()?, key[24..40].try_into()?),
            _ => (key[..32].try_into()?, key[32..].try_into()?),
        })
    }
}
