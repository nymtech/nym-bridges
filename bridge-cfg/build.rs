use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;

fn main() {
    let default_bridge_cfg = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("bridges.template.toml");
    let mut default_bridge_cfg_file = std::fs::File::open(default_bridge_cfg).unwrap();
    let mut contents = String::new();
    default_bridge_cfg_file
        .read_to_string(&mut contents)
        .unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("bridge_default.rs");
    let mut rust_interface = String::from(
        "pub fn default_bridge_config_str() -> &'static str {
r#\"",
    );
    rust_interface.push_str(&contents);
    rust_interface.push_str(
        "	\"#
}",
    );
    fs::write(&dest_path, rust_interface).unwrap();
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=../bridges.template.toml");
}
