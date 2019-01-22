extern crate gpapi;

use std::env;
use std::error::Error;

fn main() -> Result<(), Box<Error>> {
    match get_login_from_env() {
        LoginInfo {
            ref username,
            ref password,
            ref android_id,
        } => {
            let resp = gpapi::login(username, password, android_id).unwrap();
            let token = resp.get("auth").unwrap();

            let pkg_names = ["com.viber.voip", "com.foo.bar.baz.qux"]
                .iter()
                .cloned()
                .map(String::from)
                .collect();

            if let Ok(Some(resp)) = gpapi::bulk_details(pkg_names, token, android_id) {
                let as_str = gpapi::serde_json::to_string_pretty(&resp)?;
                println!("{}", as_str);
            }

            if let Ok(Some(resp)) = gpapi::details("com.viber.voip", token, android_id) {
                let as_str = gpapi::serde_json::to_string_pretty(&resp)?;
                println!("{}", as_str);
            }
        }
    };

    Ok(())
}

#[derive(Debug)]
struct LoginInfo {
    username: String,
    password: String,
    android_id: String,
}

fn get_login_from_env() -> LoginInfo {
    match (
        env::var("GOOGLE_LOGIN"),
        env::var("GOOGLE_PASSWORD"),
        env::var("ANDROID_ID"),
    ) {
        (Ok(username), Ok(password), Ok(android_id)) => LoginInfo {
            username,
            password,
            android_id,
        },
        _ => unimplemented!(),
    }
}
