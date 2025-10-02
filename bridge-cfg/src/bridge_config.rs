use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};
use toml_edit::{DocumentMut, Item, Table, value};

use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::bridge_client_config::BridgeClientConfig;

include!(concat!(env!("OUT_DIR"), "/bridge_default.rs"));

const CLIENT_PARAMS_PATH_FIELD: &str = "client_params_path";
const TRANSPORTS_FIELD: &str = "transports";
const ARGS_FIELD: &str = "args";
const TRANSPORT_TYPE_FIELD: &str = "transport_type";
const IDENTITY_KEY_FIELD: &str = "client_params_path";
const PRIVKEY_PATH_FIELD: &str = "private_ed25519_identity_key_file";

#[derive(Clone, Debug)]
pub(crate) struct BridgeConfig {
    pub(crate) inner: DocumentMut,
    pub(crate) keys: Vec<Keyfile>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let config_str = default_bridge_config_str();

        Self {
            keys: vec![],
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
            keys: Vec::new(),
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
    pub fn generate_keys(&mut self, overwrite: bool, dir: &PathBuf) -> Result<()> {
        let mut rng = rand::rngs::OsRng;
        let new_key = SigningKey::generate(&mut rng);
        let key = new_key
            .to_pkcs8_pem(LineEnding::CRLF)
            .context("failed to serialize ed25519 private key to PKCS8 PEM")?
            .as_bytes()
            .to_vec();
        let path = dir.clone().join("ed25519_identity.pem");
        let keyfile = Keyfile {
            path: path.clone(),
            key,
        };
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
            if transport_type.is_none() {
                continue;
            } else if let Some(t) = transport_type
                && !["quic_plain", "tls_plain"].contains(&t.as_str())
            {
                continue;
            }

            // only update key material if overwrite was requested or no key or keypath was defined
            if overwrite
                || !(transport_cfg.has_identity_key_bytes()
                    || transport_cfg.has_identity_key_path())
            {
                transport_cfg.set_key_path(&path);

                // if we are going to use the generated key push it into the new keys one time
                // rather than once per transport defined
                push_once.call_once(|| self.keys.push(keyfile.clone()));
            }
        }
        Ok(())
    }

    pub fn persist_keys(&self) -> Result<()> {
        for Keyfile { path, key } in &self.keys {
            let mut f = File::create(path)?;
            f.write_all(key)?;
            f.flush()?;
        }

        Ok(())
    }

    pub fn get_or_set_client_config_path(&mut self, default: PathBuf) -> PathBuf {
        match self.inner.get(CLIENT_PARAMS_PATH_FIELD) {
            Some(item) => PathBuf::from(item.as_str().unwrap()),
            None => {
                self.inner[CLIENT_PARAMS_PATH_FIELD] = value(default.to_str().unwrap());
                default
            }
        }
    }

    pub fn set_forward_address(&mut self, addr: SocketAddr) {
        self.inner["forward"]["address"] = value(addr.to_string());
    }

    pub fn set_client_config_path(&mut self, path: &Path) {
        self.inner[CLIENT_PARAMS_PATH_FIELD] = toml_edit::value(path.to_str().unwrap());
    }

    pub fn print_diff(&self, other: Option<&Self>, path: Option<PathBuf>) {
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
        for keyfile in &self.keys {
            println!("Δ {:?}", keyfile.path);
        }
    }

    /// return an error only if the file exists but fails to parse. otherwise, it will be generated /regenerated
    /// so returning `Ok(None)` is what we want.
    pub fn maybe_parse_client_config(&self) -> Result<Option<BridgeClientConfig>> {
        let path = match self.inner.get(CLIENT_PARAMS_PATH_FIELD) {
            Some(path) => PathBuf::from(path.as_str().unwrap_or("")),
            None => return Ok(None),
        };

        if !path.exists() {
            return Ok(None);
        }

        Ok(Some(BridgeClientConfig::parse_from_file(&path)?))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Keyfile {
    pub(crate) path: PathBuf,
    pub(crate) key: Vec<u8>,
}

struct TransportConfig<'a> {
    inner: &'a mut Table,
}

impl<'a> TransportConfig<'a> {
    fn new(inner: &'a mut Table) -> Self {
        Self { inner: inner }
    }

    fn transport_type(&self) -> Option<String> {
        if !self.inner.contains_key(TRANSPORT_TYPE_FIELD) {
            return None;
        }
        Some(self.inner[TRANSPORT_TYPE_FIELD].to_string())
    }

    fn has_identity_key_bytes(&self) -> bool {
        self.inner
            .get(ARGS_FIELD)
            .is_some_and(|args| args.get(IDENTITY_KEY_FIELD).is_some())
    }

    fn has_identity_key_path(&self) -> bool {
        self.inner
            .get(ARGS_FIELD)
            .is_some_and(|args| args.get(PRIVKEY_PATH_FIELD).is_some())
    }

    fn set_key_path(&mut self, path: &Path) {
        self.inner[ARGS_FIELD][IDENTITY_KEY_FIELD] = Item::None;
        self.inner[ARGS_FIELD][PRIVKEY_PATH_FIELD] = value(path.to_str().unwrap_or_default());
    }
}
