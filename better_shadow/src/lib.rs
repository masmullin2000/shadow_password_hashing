pub mod crypto;

use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Write},
    str::FromStr,
};

use crypto::{get_key, new_key, Algo};

#[derive(Debug, PartialEq)]
pub enum StorageError {
    UserFound,
    UserNotFound,
    UserDataMangled,
}
impl Error for StorageError {}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::UserFound => write!(f, "User Already Exists"),
            StorageError::UserNotFound => write!(f, "User Does Not Exist"),
            StorageError::UserDataMangled => write!(f, "User Data is mangled"),
        }
    }
}

fn get_user_data(file: &mut File, user: &str) -> Option<String> {
    let mut file_data = String::new();
    if file.read_to_string(&mut file_data).is_err() {
        None
    } else {
        for line in file_data.lines() {
            if line.starts_with(user) {
                return Some(line.to_string());
            }
        }

        None
    }
}

pub fn store_new_user(
    file: &str,
    user: &str,
    passwd: &str,
    algo: Algo,
) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(file)?;

    if get_user_data(&mut file, user).is_some() {
        Err(Box::new(StorageError::UserFound {}))
    } else {
        let (salt, key) = new_key(passwd, algo)?;
        let salt = base64::encode_config(salt, base64::CRYPT);
        let key = base64::encode_config(key, base64::CRYPT);

        let line = format!("{}:${}${}${}:::::::\n", user, algo, salt, key);

        let _ = file.write(line.as_bytes())?;

        Ok(())
    }
}

struct StoredPasswordData {
    algo: Algo,
    salt: Vec<u8>,
    key: Vec<u8>,
}

impl StoredPasswordData {
    fn new(algo: &str, salt: &str, key: &str) -> Result<Self, Box<dyn Error>> {
        Ok(StoredPasswordData {
            algo: Algo::from_str(algo)?,
            salt: base64::decode_config(salt, base64::CRYPT)?,
            key: base64::decode_config(key, base64::CRYPT)?,
        })
    }
}

fn parse_user_data(user_line: &str) -> Result<StoredPasswordData, Box<dyn Error>> {
    let parts = user_line.split(':').collect::<Vec<&str>>();
    if parts.len() < 2 {
        return Err(Box::new(StorageError::UserDataMangled {}));
    }

    let passwd_part = parts[1].split('$').collect::<Vec<&str>>();
    if passwd_part.len() < 4 {
        return Err(Box::new(StorageError::UserDataMangled {}));
    }

    StoredPasswordData::new(passwd_part[1], passwd_part[2], passwd_part[3])
}

pub fn check_user(file: &str, user: &str, passwd: &str) -> Result<bool, Box<dyn Error>> {
    let mut file = OpenOptions::new().read(true).open(file)?;

    let user_data = match get_user_data(&mut file, user) {
        Some(user_data) => user_data,
        None => return Err(Box::new(StorageError::UserNotFound {})),
    };
    
    match parse_user_data(&user_data) {
        Ok(passwd_data) => {
            let key = get_key(passwd, &passwd_data.salt, passwd_data.algo)?;
            
            use subtle::ConstantTimeEq;
            if key.ct_eq(&passwd_data.key).into() {
                return Ok(true);
            }
        },
        Err(e) => return Err(e),
    }

    Ok(false)
}
