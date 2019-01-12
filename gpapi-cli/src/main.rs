extern crate gpapi;

use std::env;
use std::error::Error;

fn main() -> Result<(), Box<Error>> {
    let bulk_details_resp = match get_login_from_env() {
        LoginInfo {
            ref username,
            ref password,
            ref android_id,
        } => {
            let resp = gpapi::login(username, password, android_id).unwrap();
            let token = resp.get("auth").unwrap();
            let pkg_names: Vec<String> = vec![String::from("com.viber.voip"), String::from("com.foo.bar.baz.qux")];
            gpapi::bulk_details(pkg_names, token, android_id)
        }
    };

    if let Ok(Some(resp)) = bulk_details_resp {
        let as_str = gpapi::serde_json::to_string_pretty(&resp)?;
        println!("reply {}", as_str);
    }

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
