extern crate base64;
extern crate byteorder;
extern crate curl;
extern crate hex;
extern crate openssl;
extern crate protobuf;

use std::env;

fn main() {
    let enc = gpapi::encrypt_login("foo", "bar").unwrap();
    println!("encrypted: {:?}", base64::encode(&enc));
    println!("base64_urlsafe: {:?}", gpapi::base64_urlsafe(&enc));

    let login_info = get_login_from_env();
    // println!("{:?}", login_info);
    gpapi::login(
        &login_info.username,
        &login_info.password,
        &login_info.android_id,
    )
    .unwrap();
}

#[derive(Debug)]
struct LoginInfo {
    username: String,
    password: String,
    android_id: String,
}

fn get_login_from_env() -> LoginInfo {
    let username = match env::var("GOOGLE_LOGIN") {
        Ok(val) => val,
        _ => unimplemented!(),
    };
    let password = match env::var("GOOGLE_PASSWORD") {
        Ok(val) => val,
        _ => unimplemented!(),
    };
    let android_id = match env::var("ANDROID_ID") {
        Ok(val) => val,
        _ => unimplemented!(),
    };

    LoginInfo {
        username: username,
        password: password,
        android_id: android_id,
    }
}
