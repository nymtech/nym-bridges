use anyhow::{Context, Result, anyhow};
use nym_bridges::config::TransportServerConfig;
use nym_bridges::transport::{ExternalizeKeyMaterial, GenerateServerConfig, GeneratedKeyMaterial};
use serde::Serialize;
use toml_edit::{DocumentMut, value};
use tracing::*;

use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/bridge_default.rs"));

const CLIENT_PARAMS_PATH_FIELD: &str = "client_params_path";
const TRANSPORTS_FIELD: &str = "transports";

#[derive(Clone, Debug)]
pub(crate) struct BridgeConfig {
    pub(crate) inner: DocumentMut,
    pub(crate) keys: Vec<GeneratedKeyMaterial>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let config_str = default_bridge_config_str();
        Self {
            keys: Vec::new(),
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
                .context("failed to parse bridge config toml")?,
            keys: Vec::new(),
        })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)
            .with_context(|| format!("failed to open bridge config at {path:?}"))?;
        let mut config_str = String::new();
        config_file
            .read_to_string(&mut config_str)
            .with_context(|| format!("failed to read bridge config at {path:?}"))?;
        Self::parse(config_str)
            .with_context(|| format!("failed to parse bridge config at {path:?}"))
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

    /// Generates any key material missing from the transports defined in this bridge
    /// configuration, delegating the actual generation to each transport's own
    /// [`GenerateServerConfig`]/[`ExternalizeKeyMaterial`] implementations rather than
    /// hand-rolling it here. If `overwrite` is true, key material is regenerated even if it
    /// already exists.
    ///
    /// Each transport that needs generation gets its own independent key (and, for the host
    /// identity, its own file under `dir`) -- see `nym_bridges::transport::{quic, tls, ssh}` for
    /// the per-transport filenames used. A transport whose identity is already valid (an inline
    /// key, or a `private_ed25519_identity_key_file` pointing at a file that actually exists) is
    /// left completely untouched.
    ///
    /// Regenerating any transport re-serializes the whole `transports` array through the typed
    /// config structs (canonical formatting) -- everything else in the document (`forward`,
    /// `public_ips`, `client_params_path`) is left byte-for-byte untouched.
    pub fn generate_keys(&mut self, overwrite: bool, dir: &Path) -> Result<()> {
        debug!("generating keys overwrite:{overwrite}, dir: {dir:?}");

        let mut transports: Vec<TransportServerConfig> = self
            .inner
            .get(TRANSPORTS_FIELD)
            .ok_or(anyhow!("no transports defined"))?
            .as_array_of_tables()
            .ok_or(anyhow!("transports is not an array of tables"))?
            .iter()
            .map(|table| {
                // `Table::to_string()` only renders dotted-key values and silently drops
                // ordinary `[section]` sub-tables like `args` -- wrap it as a standalone
                // document first so it renders (and thus re-parses) correctly.
                let mut doc = DocumentMut::new();
                *doc.as_table_mut() = table.clone();
                toml::from_str(&doc.to_string()).context("failed to parse transport entry")
            })
            .collect::<Result<_>>()?;

        let mut rng = rand::rng();

        for transport in &mut transports {
            match transport {
                TransportServerConfig::QuicPlain(cfg) => {
                    let valid = identity_is_valid(
                        &cfg.identity_key,
                        &cfg.private_ed25519_identity_key_file,
                    );
                    if overwrite || !valid {
                        // Clear whenever we're regenerating -- not just on `overwrite` -- so a
                        // stale/broken `private_ed25519_identity_key_file` reference doesn't make
                        // `generate_config` think an identity is already configured.
                        cfg.identity_key = None;
                        cfg.private_ed25519_identity_key_file = None;
                        let (updated, generated) = regenerate(std::mem::take(cfg), dir, &mut rng)?;
                        *cfg = updated;
                        self.keys.extend(generated);
                    }
                }
                TransportServerConfig::TlsPlain(cfg) => {
                    let valid = identity_is_valid(
                        &cfg.identity_key,
                        &cfg.private_ed25519_identity_key_file,
                    );
                    if overwrite || !valid {
                        cfg.identity_key = None;
                        cfg.private_ed25519_identity_key_file = None;
                        let (updated, generated) = regenerate(std::mem::take(cfg), dir, &mut rng)?;
                        *cfg = updated;
                        self.keys.extend(generated);
                    }
                }
                TransportServerConfig::SshPlain(cfg) => {
                    let valid = identity_is_valid(
                        &cfg.identity_key,
                        &cfg.private_ed25519_identity_key_file,
                    );
                    let needs_generation = overwrite || !valid || cfg.client_auth_key.is_none();
                    if needs_generation {
                        // Only clear the identity fields if the identity itself needs
                        // regenerating -- if it's already valid and only `client_auth_key` is
                        // missing, leave it untouched; `generate_config` fills each key
                        // independently based on which fields are still unset.
                        if overwrite || !valid {
                            cfg.identity_key = None;
                            cfg.private_ed25519_identity_key_file = None;
                        }
                        if overwrite {
                            cfg.client_auth_key = None;
                        }
                        let (updated, generated) = regenerate(std::mem::take(cfg), dir, &mut rng)?;
                        *cfg = updated;
                        self.keys.extend(generated);
                    }
                }
            }
        }

        #[derive(Serialize)]
        struct TransportsOnly<'a> {
            transports: &'a [TransportServerConfig],
        }

        let serialized = toml::to_string(&TransportsOnly {
            transports: &transports,
        })
        .context("failed to serialize regenerated transports")?;
        let parsed: DocumentMut = serialized
            .parse()
            .context("failed to reparse regenerated transports")?;
        self.inner[TRANSPORTS_FIELD] = parsed[TRANSPORTS_FIELD].clone();

        Ok(())
    }

    pub fn persist_keys(&self, out_dir: &Path) -> Result<()> {
        debug!("persisting keys at: {out_dir:?}");
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("failed to create key directory {out_dir:?}"))?;
        for (path, key) in keys_out(&self.keys, out_dir) {
            let mut f = File::create(&path)
                .with_context(|| format!("failed to create key file {path:?}"))?;
            f.write_all(&key)?;
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
        let mut ip_array = toml_edit::Array::new();
        for ip in ips {
            ip_array.push(ip.to_string());
        }
        self.inner["public_ips"] = toml_edit::value(ip_array);
    }

    pub fn get_public_ips(&self) -> Vec<std::net::IpAddr> {
        if let Some(public_ips) = self.inner.get("public_ips").and_then(|v| v.as_array()) {
            public_ips
                .iter()
                .filter_map(|s| s.as_str().and_then(|s| s.parse::<std::net::IpAddr>().ok()))
                .collect()
        } else {
            Vec::new()
        }
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
        for path in key_paths(&self.keys, key_dir) {
            println!("Δ {:?}", path);
        }
    }
}

/// Whether a transport's identity is already usable as-is: an inline key is always sufficient
/// regardless of validity (it's not this tool's job to second-guess a user-provided key), while a
/// file-path reference is only sufficient if that file actually exists.
fn identity_is_valid(inline: &Option<String>, file: &Option<PathBuf>) -> bool {
    inline.is_some() || file.as_deref().is_some_and(Path::exists)
}

/// Generate any missing key material for `cfg` and move its host identity out to a file under
/// `dir`, via the transport's own [`GenerateServerConfig`]/[`ExternalizeKeyMaterial`] impls.
fn regenerate<T: GenerateServerConfig + ExternalizeKeyMaterial>(
    cfg: T,
    dir: &Path,
    rng: &mut (impl rand::CryptoRng + ?Sized),
) -> Result<(T, Vec<GeneratedKeyMaterial>)> {
    cfg.generate_config(rng)
        .externalize_keys(dir)
        .context("failed to externalize generated key material")
}

/// Where each generated key would land under `dir`, keyed off just the filename embedded in the
/// material (not its full path -- callers may want these staged somewhere other than where the
/// config itself will eventually point, e.g. a scratch tempdir for dry-run previews).
fn key_paths(keys: &[GeneratedKeyMaterial], dir: &Path) -> Vec<PathBuf> {
    keys.iter()
        .filter_map(|k| k.path.file_name().map(|name| dir.join(name)))
        .collect()
}

fn keys_out(keys: &[GeneratedKeyMaterial], dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    keys.iter()
        .filter_map(|k| {
            k.path
                .file_name()
                .map(|name| (dir.join(name), k.pem_bytes.clone()))
        })
        .collect()
}

#[cfg(test)]
mod test {

    mod key_generation {
        use super::super::*;
        use nym_bridges::types::Sufficiency;
        use toml_edit::{Item, value};

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

        const KEY_TEST_SSH: &str = r##"public_ips = ["192.168.100.3"]
[forward]
address = "[::1]:50001"
[[transports]]
transport_type = "ssh_plain"
[transports.args]
listen = "[::]:4422"
"##;

        const KEY_TEST_MULTI: &str = r##"public_ips = ["192.168.100.3"]
[forward]
address = "[::1]:50001"
[[transports]]
transport_type = "quic_plain"
[transports.args]
stateless_retry = false
listen = "[::]:4433"

[[transports]]
transport_type = "ssh_plain"
[transports.args]
listen = "[::]:4422"
"##;

        fn init() {
            // let level = tracing_subscriber::filter::LevelFilter::DEBUG;
            // crate::test::init_subscriber(Some(level));
            // println!();
        }

        /// Point the (only) transport's `private_ed25519_identity_key_file` directly at `path`,
        /// clearing any inline `identity_key` -- used to set up an "already has a key file"
        /// fixture without going through `generate_keys` itself.
        fn set_key_path(cfg: &mut BridgeConfig, path: &Path) {
            for entry in cfg
                .inner
                .get_mut(TRANSPORTS_FIELD)
                .ok_or(anyhow!("no transports defined"))
                .unwrap()
                .as_array_of_tables_mut()
                .unwrap()
                .iter_mut()
            {
                entry["args"]["identity_key"] = Item::None;
                entry["args"]["private_ed25519_identity_key_file"] =
                    value(path.to_str().unwrap_or_default());
            }
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
        // should generate a new key, using the configured key dir (the original, nonexistent
        // path is not reused -- see the module's doc comment on `generate_keys`).
        #[test]
        fn nonexistent_key_no_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
        }

        // key specified by file path where the key file doesn't exist, overwrite allowed
        // should generate a new key.
        #[test]
        fn nonexistent_key_yes_overwrite() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
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
            set_key_path(&mut cfg, &fpath);
            info!("{}", cfg.serialize());
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(cfg.keys.is_empty());
        }

        // key specified by file path where the key file DOES exist, overwrite allowed
        // should generate a new key.
        #[test]
        fn existing_key_yes_overwrite() {
            let tmp = tempdir::TempDir::new("key_gen_test").unwrap();
            let fpath = tmp.path().join("ed25519_bridge_identity.pem");
            std::fs::File::create(&fpath).unwrap();
            assert!(fpath.exists());

            let mut cfg = BridgeConfig::parse(KEY_TEST_2).unwrap();
            set_key_path(&mut cfg, &fpath);
            cfg.generate_keys(true, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());
        }

        // ssh_plain transports previously had no key generation support at all -- confirm both
        // the host identity and the separate client_auth_key now get generated.
        #[test]
        fn ssh_transport_generates_both_keys() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_SSH).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert!(!cfg.keys.is_empty());

            let out: nym_bridges::config::PersistedServerConfig =
                toml::from_str(&cfg.serialize()).unwrap();
            match &out.transports[0] {
                TransportServerConfig::SshPlain(ssh_cfg) => {
                    assert!(ssh_cfg.is_sufficient());
                    assert!(ssh_cfg.client_auth_key.is_some());
                }
                other => panic!("expected an ssh_plain transport, got {other:?}"),
            }
        }

        // when multiple transports each need key material, every one should get its own
        // independently generated key/file rather than sharing a single key across all of them.
        #[test]
        fn multiple_transports_get_independent_keys() {
            let mut cfg = BridgeConfig::parse(KEY_TEST_MULTI).unwrap();
            cfg.generate_keys(false, &PathBuf::from("./")).unwrap();
            assert_eq!(cfg.keys.len(), 2);

            let out: nym_bridges::config::PersistedServerConfig =
                toml::from_str(&cfg.serialize()).unwrap();
            let mut identity_files: Vec<_> = out
                .transports
                .iter()
                .map(|t| match t {
                    TransportServerConfig::QuicPlain(c) => {
                        c.private_ed25519_identity_key_file.clone().unwrap()
                    }
                    TransportServerConfig::SshPlain(c) => {
                        c.private_ed25519_identity_key_file.clone().unwrap()
                    }
                    TransportServerConfig::TlsPlain(_) => unreachable!(),
                })
                .collect();
            identity_files.sort();
            identity_files.dedup();
            assert_eq!(
                identity_files.len(),
                2,
                "each transport should have its own identity key file"
            );
        }
    }
}
