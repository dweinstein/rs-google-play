#![allow(non_snake_case)]

extern crate gpapi;
#[macro_use]
extern crate clap;

extern crate serde_json;

use clap::App;
use gpapi::Gpapi;

use std::env;
use std::error::Error;

fn main() -> Result<(), Box<Error>> {
    let cli_yaml_def = load_yaml!("cli.yml");
    let matches = App::from_yaml(cli_yaml_def).get_matches();

    let api = match get_login_from_env() {
        LoginInfo {
            username,
            password,
            gsf_id,
        } => {
            let mut api = Gpapi::new(username, password, gsf_id);
            api.authenticate()?;
            api
        }
    };

    if let Some(matches) = matches.subcommand_matches("bulk-details") {
        let pkgs = matches.values_of("PKGS").unwrap().collect::<Vec<&str>>();
        let bulk_details = api.bulk_details(&pkgs).ok();
        let as_str = serde_json::to_string_pretty(&bulk_details)?;
        println!("{}", as_str);
    } else if let Some(matches) = matches.subcommand_matches("details") {
        let pkg = matches.value_of("PKG").unwrap();
        let details = api.details(&pkg)?.unwrap();
        let as_str = serde_json::to_string_pretty(&details)?;
        println!("{}", as_str);
    } else if let Some(matches) = matches.subcommand_matches("get-download-url") {
        let pkg = matches.value_of("PKG").unwrap();
        let vc: u64 = matches.value_of("VC").unwrap().parse().unwrap();
        let download_url = api.get_download_url(&pkg, vc)?.unwrap();
        println!("{}", download_url);
    } else {
        return Err("Subcommand required".into())
    }
    Ok(())
}

#[derive(Debug)]
struct LoginInfo {
    username: String,
    password: String,
    gsf_id: String,
}

fn get_login_from_env() -> LoginInfo {
    match (
        env::var("GOOGLE_LOGIN"),
        env::var("GOOGLE_PASSWORD"),
        env::var("ANDROID_ID"),
    ) {
        (Ok(username), Ok(password), Ok(gsf_id)) => LoginInfo {
            username,
            password,
            gsf_id,
        },
        _ => unimplemented!(),
    }
}
