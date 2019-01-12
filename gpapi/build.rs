extern crate protoc_rust;

use protoc_rust::Customize;
use std::path::Path;

fn main() {
    if !Path::new("src/protos/googleplay.rs").exists() {
        protoc_rust::run(protoc_rust::Args {
            out_dir: "src/protos",
            input: &["protos/googleplay.proto"],
            includes: &["protos"],
            customize: Customize {
                expose_fields: Some(true),
                generate_accessors: Some(false),
                serde_derive: Some(true),
                ..Default::default()
            },
        })
        .expect("protoc");
    }
}
