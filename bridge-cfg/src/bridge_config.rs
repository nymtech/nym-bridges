use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};
use toml_edit::{DocumentMut, Item, Table, value};
use tracing::*;

use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/bridge_default.rs"));

const CLIENT_PARAMS_PATH_FIELD: &str = "client_params_path";
const TRANSPORTS_FIELD: &str = "transports";
const ARGS_FIELD: &str = "args";
const TRANSPORT_TYPE_FIELD: &str = "transport_type";
const IDENTITY_KEY_FIELD: &str = "identity_key";
const IDENTITY_KEY_PATH_FIELD: &str = "private_ed25519_identity_key_file";

#[derive(Clone, Debug)]
pub(crate) struct BridgeConfig {
    pub(crate) inner: DocumentMut,
    pub(crate) keys: KeyFiles,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let config_str = default_bridge_config_str();
        Self {
            keys: KeyFiles::new(),
            inner: config_str
                .parse::<DocumentMut>()
                .expect("failed to parse default bridge config template"),
        }
    }
}

impl BridgeConfig {
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: config_str
                .as_ref()
                .parse::<DocumentMut>()
                .context("failed to parse config")?,
            keys: KeyFiles::new(),
        })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        Self::parse(config_str)
    }

    pub fn serialize(&self) -> String {
        self.inner.to_string()
    }

    pub fn serialize_to_file(&self, path: PathBuf) -> Result<()> {
        let mut out_file = std::fs::File::create(path)?;
        out_file
            .write_all(self.serialize().as_bytes())
            .context("failed to serialize bridge config to file")
    }

    /// Generates keys for the transports that are defined in the Bridge configuration. If
    /// `overwrite` is true it will generate keys even if the key file exists at the defined path or
    /// the `identity_key` field if defined -- If persisted, this will overwrite existing keys.
    ///
    /// NOTE: In the initial version of the bridge runner this function is generating one single key
    /// and using it for all defined transports as they all rely on the same key type and really we
    /// will only be using one of the transports initially anyways. TODO: This should be updated in
    /// the next version to allow the transport types to generate their own initial state / key
    /// material rather than trying to do it for them.
    pub fn generate_keys(&mut self, overwrite: bool, dir: &Path) -> Result<()> {
        debug!("generating keys overwrite:{overwrite}, dir: {dir:?}");
        let mut rng = rand::rngs::OsRng;
        let new_key = SigningKey::generate(&mut rng);
        let key = new_key
            .to_pkcs8_pem(LineEnding::CRLF)
            .context("failed to serialize ed25519 private key to PKCS8 PEM")?
            .as_bytes()
            .to_vec();
        let key_name = "ed25519_bridge_identity.pem";
        let push_once = std::sync::Once::new();

        for entry in self
            .inner
            .get_mut(TRANSPORTS_FIELD)
            .ok_or(anyhow!("no transports defined"))?
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
        {
            let mut transport_cfg = TransportConfig::new(entry);
            let transport_type = transport_cfg.transport_type();
            debug!("generating keys for {:?}", transport_type);
            if transport_type.is_none() {
                continue;
            } else if let Some(t) = transport_type
                && !["quic_plain", "tls_plain"].contains(&t.trim().replace("\"", "").as_str())
            {
                continue;
            }

            // only update key material if overwrite was requested or no key or keypath was defined
            if overwrite || !transport_cfg.has_identity_key() {
                let path = &transport_cfg
                    .get_identity_key_path()
                    .unwrap_or(dir.join(key_name));
                debug!("key will be used - path: {path:?}");
                transport_cfg.set_key_path(path);

                // if we are going to use the generated key push it into the new keys one time
                // rather than once per transport defined
                debug!("key added to keyfiles");
                push_once.call_once(|| self.keys.add_key(key_name, &key));
            }
        }
        Ok(())
    }

    pub fn persist_keys(&self, out_dir: &Path) -> Result<()> {
        debug!("persisting keys at: {out_dir:?}");
        for (path, key) in &self.keys.keys_out(out_dir) {
            let mut f = File::create(path)?;
            f.write_all(key)?;
            f.flush()?;
            debug!("wrote key at {path:?}");
        }

        Ok(())
    }

    pub fn set_forward_address(&mut self, addr: SocketAddr) {
        debug!("setting bridge forward address: {addr}");
        self.inner["forward"]["address"] = value(addr.to_string());
    }

    pub fn get_client_config_path(&self) -> Option<PathBuf> {
        match self.inner.get(CLIENT_PARAMS_PATH_FIELD) {
            Some(path) => Some(PathBuf::from(path.as_str().unwrap_or(""))),
            None => None,
        }
    }

    pub fn set_client_config_path(&mut self, path: &Path) {
        debug!("setting client_param_filepath for bridge config: {path:?}");
        self.inner[CLIENT_PARAMS_PATH_FIELD] = toml_edit::value(path.to_str().unwrap());
    }

    pub fn set_public_ips(&mut self, ips: Vec<std::net::IpAddr>) {
        debug!("setting public IPs for bridge config: {:?}", ips);
        let ip_strings: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        self.inner["public_ips"] = toml_edit::value(ip_strings);
    }

    pub fn print_diff(&self, other: Option<&Self>, path: Option<PathBuf>, key_dir: &Path) {
        let old = other.map(Self::serialize).unwrap_or_default();
        let new = self.serialize();
        let diff = similar::TextDiff::from_lines(&old, &new);

        if let Some(p) = path {
            println!(" > {p:?}:");
        }
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };

            print!("{sign} {change}");
        }
        println!();
        for path in &self.keys.key_paths(key_dir) {
            println!("Δ {:?}", path);
        }
    }
}

/// This attempts to track a set of generated keys, while being careful about serializing to the
/// desired disk locations until we are ready.
///
/// The strategy here is to create a tempdir that will contain the keys while we are in a dynamic or
/// non-committed state. Once we go to serialize a configuration the path will be updated to the
/// final path of the key directory and the key will be written there.
#[derive(Clone, Debug)]
pub(crate) struct KeyFiles {
    pub(crate) keys: Vec<Keyfile>,
}

impl KeyFiles {
    fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn key_paths(&self, dir: &Path) -> Vec<PathBuf> {
        self.keys.iter().map(|k| dir.join(&k.fname)).collect()
    }

    fn keys_out(&self, dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        self.keys
            .iter()
            .map(|k| (dir.join(&k.fname), k.key.clone()))
            .collect()
    }

    fn add_key(&mut self, fname: &str, bytes: &[u8]) {
        self.keys.push(Keyfile {
            fname: fname.to_string(),
            key: bytes.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Keyfile {
    pub(crate) fname: String,
    pub(crate) key: Vec<u8>,
}

struct TransportConfig<'a> {
    inner: &'a mut Table,
}

impl<'a> TransportConfig<'a> {
    fn new(inner: &'a mut Table) -> Self {
        Self { inner }
    }

    fn transport_type(&self) -> Option<String> {
        if !self.inner.contains_key(TRANSPORT_TYPE_FIELD) {
            return None;
        }
        Some(self.inner[TRANSPORT_TYPE_FIELD].to_string())
    }

    fn has_identity_key(&self) -> bool {
        if self.has_identity_key_bytes() {
            return true;
        }

        self.get_identity_key_path().is_some_and(|p| p.exists())
    }

    fn has_identity_key_bytes(&self) -> bool {
        self.inner
            .get(ARGS_FIELD)
            .is_some_and(|args| args.get(IDENTITY_KEY_FIELD).is_some())
    }

    fn get_identity_key_path(&self) -> Option<PathBuf> {
        self.inner
            .get(ARGS_FIELD)?
            .get(IDENTITY_KEY_PATH_FIELD)?
            .as_str()
            .map(PathBuf::from)
    }

    fn set_key_path(&mut self, path: &Path) {
        self.inner[ARGS_FIELD][IDENTITY_KEY_FIELD] = Item::None;
        self.inner[ARGS_FIELD][IDENTITY_KEY_PATH_FIELD] = value(path.to_str().unwrap_or_default());
    }
}

#[cfg(test)]
mod test {

    mod key_generation {
        use super::super::*;

        const KEY_TEST_0: &str = r##"public_ips = ["192.168.100.3"]
[forward]
address = "[::1]:50001"
[[transports]]
transport_type = "quic_plain"
[transports.args]
stateless_retry = false
listen = "[::]:4433"
"##;

        const KEY_TEST_1: &str = r##"public_ips = ["192.168.100.3"]
[forward]
address = "[::1]:50001"
[[transports]]
transport_type = "quic_plain"
[transports.args]
stateless_retry = false
listen = "[::]:4433"
identity_key = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk="
"##;

        const KEY_TEST_2: &str = r##"public_ips = ["192.168.100.3"]
[forward]
address = "[::1]:50001"
[[transports]]
transport_type = "quic_plain"
[transports.args]
stateless_retry = false
listen = "[::]:4433"
private_ed25519_identity_key_file = "/dev/null/ed25519_bridge_identity.pem"
"##;

        fn init() {
            // let level = tracing_subscriber::filter::LevelFilter::DEBUG;
            // crate::test::init_subscriber(Some(level));
            // println!();
        }

        // no key specified with overwrite disallowed
        // should generate a new key using the specified key dir path
        #[test]
        fn no_key_no_overwrite() {
            init();
            let mut cfg = BridgeConfig::parse(KEY_TEST_0).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
        }

        // no key specified with overwrite allowed
        // should generate a new key using the specified key dir path
        #[test]
        fn no_key_yes_overwrite() {
            init();
            let mut cfg = BridgeConfig::parse(KEY_TEST_0).unwrap();
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
        }

        // key specified by base64 string with overwrite disallowed
        // should not generate any key
        #[test]
        fn base64_key_no_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_1).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(cfg.keys.is_empty());
        }

        // key specified by base64 string with overwrite allowed
        // should generate a new key, set path using the specified key dir path, and set identity to null
        #[test]
        fn base64_key_yes_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_1).unwrap();
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
        }

        // key specified by file path where the key file doesn't exist, overwrite disallowed
        // should generate a new key, using the pre-existing path.
        #[test]
        fn nonexistent_key_no_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
            // todo: check that path is unchanged.
        }

        // key specified by file path where the key file doesn't exist, overwrite allowed
        // should generate a new key, using the pre-existing path.
        #[test]
        fn nonexistent_key_yes_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
            // todo: check that path is unchanged.
        }

        // key specified by file path where the key file DOES exist, overwrite disallowed
        // should NOT generate a new key
        #[test]
        fn existing_key_no_overwrite() {
            let tmp = tempdir::TempDir::new("key_gen_test").unwrap();
            let fpath = tmp.path().join("ed25519_bridge_identity.pem");
            std::fs::File::create(&fpath).unwrap();
            assert!(fpath.exists());

            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.inner
                .get_mut(TRANSPORTS_FIELD)
                .ok_or(anyhow!("no transports defined"))
                .unwrap()
                .as_array_of_tables_mut()
                .unwrap()
                .iter_mut()
                .for_each(|entry| {
                    let mut transport_cfg = TransportConfig::new(entry);
                    transport_cfg.set_key_path(&fpath);
                });
            info!("{}", cfg.serialize());
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(cfg.keys.is_empty());
        }

        // key specified by file path where the key file DOES exist, overwrite allowed
        // should generate a new key, using the pre-existing path.
        #[test]
        fn existing_key_yes_overwrite() {
            let tmp = tempdir::TempDir::new("key_gen_test").unwrap();
            let fpath = tmp.path().join("ed25519_bridge_identity.pem");
            std::fs::File::create(&fpath).unwrap();
            assert!(fpath.exists());

            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.inner
                .get_mut(TRANSPORTS_FIELD)
                .ok_or(anyhow!("no transports defined"))
                .unwrap()
                .as_array_of_tables_mut()
                .unwrap()
                .iter_mut()
                .for_each(|entry| {
                    let mut transport_cfg = TransportConfig::new(entry);
                    transport_cfg.set_key_path(&fpath);
                });
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
            // todo: check that path is unchanged.
        }
    }
}
