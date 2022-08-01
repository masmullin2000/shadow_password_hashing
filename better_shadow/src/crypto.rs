use std::{error::Error, str::FromStr};

use argon2::Argon2;
use hmac::{
    digest::{FixedOutput, KeyInit},
    Hmac,
};
use pbkdf2::pbkdf2;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

pub const KEY_LEN: usize = 32; //256 bits
pub const SALT_SZ: usize = KEY_LEN;

const ITERATIONS: u32 = 2_500_000;
const ARGON_MEMORY: u32 = 131_072;  // 128 MB
const ARGON_ITERATIONS: u32 = 15;
const ARGON_PARALLEL: u32 = 16;

//const ITERATIONS: u32 = 310_000; // OWASP recommended minimum PBKDF
//const ARGON_MEMORY: u32 = 15_320; //  15 MB min per OWASP
//const ARGON_ITERATIONS: u32 = 2; // min OWASP
//const ARGON_PARALLEL: u32 = 1; // min OWASP

#[derive(Copy, Clone)]
pub enum Algo {
    PBKDF2,
    ARGON2,
    Both,
}

#[derive(Debug)]
struct AlgoError {}
impl Error for AlgoError {}
impl std::fmt::Display for AlgoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown Algorithm")
    }
}

impl std::fmt::Display for Algo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            Algo::PBKDF2 => "7".to_string(),
            Algo::ARGON2 => "8".to_string(),
            Algo::Both => "9".to_string(),
        };
        write!(f, "{}", out)
    }
}

impl FromStr for Algo {
    type Err = Box<dyn Error>;

    fn from_str(c: &str) -> Result<Self, Box<dyn Error>> {
        match c {
            "7" => Ok(Algo::PBKDF2),
            "8" => Ok(Algo::ARGON2),
            "9" => Ok(Algo::Both),
            _ => Err(Box::new(AlgoError {})),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KeyDerivationError {
    SaltTooShort,
    PassTooShort,
    ArgonError(String),
}
impl std::error::Error for KeyDerivationError {}
impl std::fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDerivationError::SaltTooShort => write!(f, "Salt too short"),
            KeyDerivationError::PassTooShort => write!(f, "Pass too short"),
            KeyDerivationError::ArgonError(e) => write!(f, "Argon Error: {}", e),
        }
    }
}

#[derive(Debug)]
pub struct SaltIncorrectLengthError {}
impl std::fmt::Display for SaltIncorrectLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt length must be a multiple of 8 (bytes)")
    }
}
impl Error for SaltIncorrectLengthError {}

pub fn gen_salt<const L: usize>() -> Result<Vec<u8>, SaltIncorrectLengthError> {
    if L % 8 != 0 || L < 8 {
        return Err(SaltIncorrectLengthError {});
    }

    let sz = L / 8;
    let mut rng = ChaCha20Rng::from_entropy();
    let v: Vec<u64> = (0..sz).map(|_| rng.next_u64()).collect();

    let mut res = Vec::new();
    v.iter().for_each(|&u| res.extend(&u.to_ne_bytes()));

    Ok(res)
}

fn pbkdf_2<const I: u32, const L: usize, T>(
    bytes: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>>
where
    T: FixedOutput + KeyInit + Clone + Sync,
{
    let pbkdf = pbkdf2::<T>;
    let mut result = vec![0; L];
    pbkdf(bytes, salt, I, &mut result);

    Ok(result)
}

fn pbkdf2_def(passwd: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    pbkdf_2::<ITERATIONS, KEY_LEN, Hmac<Sha256>>(passwd, salt)
}

fn argon_2<const M: u32, const I: u32, const P: u32, const L: usize>(
    bytes: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    match argon2::Params::new(M, I, P, Some(L)) {
        Ok(params) => {
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::default(),
                params,
            );
            let mut result = vec![0; L];
            if argon2.hash_password_into(bytes, salt, &mut result).is_err() {
                return Err(Box::new(KeyDerivationError::ArgonError(
                    "Hashing Error".to_string(),
                )));
            }
            Ok(result)
        }
        Err(e) => {
            let err_str = format!("Params Error: {}", e);
            Err(Box::new(KeyDerivationError::ArgonError(err_str)))
        }
    }
}

fn argon2_def(passwd: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    argon_2::<ARGON_MEMORY, ARGON_ITERATIONS, ARGON_PARALLEL, KEY_LEN>(passwd, salt)
}

fn both_hash(passwd: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key_1 = argon2_def(passwd, salt)?;
    let key_2 = pbkdf2_def(passwd, salt)?;
    Ok(key_1
        .into_iter()
        .zip(key_2.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect())
}

pub fn get_key(passwd: &str, salt: &[u8], algo: Algo) -> Result<Vec<u8>, Box<dyn Error>> {
    let kdf = match algo {
        Algo::PBKDF2 => pbkdf2_def,
        Algo::ARGON2 => argon2_def,
        Algo::Both => both_hash, 
    };

    kdf(passwd.as_bytes(), salt)
}

pub fn new_key(passwd: &str, algo: Algo) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let salt = gen_salt::<SALT_SZ>()?;
    let key = get_key(passwd, &salt, algo)?;

    Ok((salt, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(expected_result: &str, result: Vec<u8>) {
        let result = hex::encode(&result);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn pbkdf2_test_vector1() {
        let expected_result_str = r#"
55ac046e56e3089fec1691c22544b605
f94185216dde0465e68b9d57c20dacbc
49ca9cccf179b645991664b39d77ef31
7c71b845b1e30bd509112041d3a19783
"#;
        let expected_result = expected_result_str.replace('\n', "");

        let result =
            pbkdf_2::<1, 64, Hmac<Sha256>>("passwd".as_bytes(), "salt".as_bytes()).unwrap();
        check(&expected_result, result);
    }

    #[test]
    fn pbkdf2_test_vector2() {
        let expected_result_str = r#"
4ddcd8f60b98be21830cee5ef22701f9
641a4418d04c0414aeff08876b34ab56
a1d425a1225833549adb841b51c9b317
6a272bdebba1d078478f62b397f33c8d
"#;
        let expected_result = expected_result_str.replace('\n', "");

        let result =
            pbkdf_2::<80_000, 64, Hmac<Sha256>>("Password".as_bytes(), "NaCl".as_bytes()).unwrap();
        check(&expected_result, result);
    }

    #[test]
    fn argon2_test_v1() {
        let expected_result_str = r#"
6f2dbd9290b640ea4ac455036a1025a7
9f5c39613e1e76670700f37176545051
"#;
        let expected_result = expected_result_str.replace('\n', "");
        let result =
            argon_2::<16, 2, 1, 32>("password123".as_bytes(), "aaaaaaaa".as_bytes()).unwrap();

        check(&expected_result, result);
    }

    #[test]
    fn argon2_test_v2() {
        let expected_result_str = r#"
0608a1d736d54984cdb356b1becc9e6e
5eda3728a64eefa7d1386f41fef8a32c
"#;
        let expected_result = expected_result_str.replace('\n', "");
        let result =
            argon_2::<1024, 16, 8, 32>("password123".as_bytes(), "aaaaaaaa".as_bytes()).unwrap();

        check(&expected_result, result);
    }
}
