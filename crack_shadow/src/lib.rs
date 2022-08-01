use anyhow::Result;
use rayon::prelude::*;
use sha_crypt::{sha512_crypt_b64, Sha512Params};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
};

pub const ITERATIONS: usize = 5_000;

fn get_user_salt_key_from_shadow(line: &str) -> Option<(&str, &str, &str)> {
    let entry: Vec<&str> = line.split(':').collect();
    if entry.len() > 2 && entry[1].starts_with("$6$") {
        let user = entry[0];
        let data = &entry[1][3..];

        let data: Vec<&str> = data.split('$').collect();
        if data.len() == 2 {
            let (salt, key) = (data[0], data[1]);
            Some((user, salt, key))
        } else {
            None
        }
    } else {
        None
    }
}

fn search_for_key(salt: &str, key_to_find: &str, words: &Vec<&str>) -> Option<String> {
    let found = AtomicBool::new(false);
    let params = Sha512Params::new(ITERATIONS).expect("param error");

    let x: Vec<String> = words
        .par_iter()
        .filter_map(|&password| {
            if !found.load(Ordering::SeqCst) {
                let possible_key = sha512_crypt_b64(password.as_bytes(), salt.as_bytes(), &params)
                    .expect("hash failure");

                if key_to_find == possible_key {
                    found.store(true, Ordering::SeqCst);
                    Some(password.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if x.len() == 1 {
        Some(x[0].clone())
    } else {
        None
    }
}

pub fn crack_shadow(shadow: &str, wordlist: &str) -> Result<HashMap<String, String>> {
    let mut shadow_file = File::open(shadow)?;
    let mut shadow_reader = String::new();
    shadow_file.read_to_string(&mut shadow_reader)?;

    let mut word_file = File::open(wordlist)?;
    let mut word_reader = String::new();
    word_file.read_to_string(&mut word_reader)?;

    let word_list: Vec<&str> = word_reader.lines().collect();

    let pass_found_list: HashMap<String, String> = shadow_reader
        .lines()
        .par_bridge()
        .filter_map(|line| {
            if let Some((user, salt, key)) = get_user_salt_key_from_shadow(line) {
                search_for_key(salt, key, &word_list).map(|pword| (user.to_string(), pword))
            } else {
                None
            }
        })
        .collect();

    Ok(pass_found_list)
}
