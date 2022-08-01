use std::{error::Error, io::ErrorKind};

use clap::Parser;
use lib::{check_user, crypto::Algo, store_new_user};

#[derive(Parser)]
struct Args {
    #[clap(short, long, value_parser)]
    username: String,

    #[clap(short, long, value_parser)]
    passwd: String,

    #[clap(short, long, value_parser, default_value = "passwrds.bin")]
    file: String,

    #[clap(short, long, value_parser, default_value = "pbkdf2")]
    algorithm: String,

    #[clap(short, long, action)]
    new_user: bool,
}

fn get_algo(algo_str: &str) -> Result<Algo, Box<dyn Error>> {
    match algo_str {
        "pbkdf2" => Ok(Algo::PBKDF2),
        "argon2" => Ok(Algo::ARGON2),
        "both" => Ok(Algo::Both),
        _ => {
            eprintln!("Unknown Algorithm");
            Err(Box::new(std::io::Error::new(ErrorKind::NotFound, "Algorithm Not Found")))
        },
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.new_user {
        let algo = get_algo(&args.algorithm)?;
        store_new_user(&args.file, &args.username, &args.passwd, algo)?;
    } else {
        match check_user(&args.file, &args.username, &args.passwd) {
            Ok(true) => println!("User is validated"),
            Ok(false) => println!("User is not validated"),
            Err(e) => eprintln!("{e}"),
        }
    }

    Ok(())
}
