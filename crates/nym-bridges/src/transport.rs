use std::path::{Path, PathBuf};

use crate::error::TransportError;
use crate::transport::tls::certs::ServerConfigSource;

pub mod quic;
pub mod ssh;
pub mod tls;

/// Implemented by each transport's `ServerConfig` to fill in any key material it's still missing,
/// generating fresh material via `rng`.
///
/// Every other field (listen address, connection limits, transport-specific knobs like SSH's
/// `expected_username`) is set the ordinary way -- `Self::default()`, optionally with a
/// struct-update override -- before calling this; there's no separate params type, since each
/// `ServerConfig` already carries exactly the fields generation needs to inspect (a key field
/// already `Some` means "reuse this", `None` means "generate one").
///
/// Generation never touches the filesystem and can't fail: any key material it invents is
/// embedded directly in the returned config (e.g. as a base64 `identity_key`). Moving that inline
/// material out to a file on disk is a distinct, separate, fallible step -- see
/// [`ExternalizeKeyMaterial`].
///
/// Implemented internally within `nym-bridges` for each transport (see the `quic`, `tls`, and
/// `ssh` modules); external tooling (e.g. `bridge-cfg`) drives generation generically rather than
/// special-casing each transport type.
pub trait GenerateServerConfig: Default + Sized {
    /// Fill in any key material `self` is still missing, generating fresh material via `rng`.
    /// Fields that are already set (e.g. a pre-existing `identity_key` or
    /// `private_ed25519_identity_key_file`) are left untouched.
    fn generate_config<R: rand::CryptoRng + ?Sized>(self, rng: &mut R) -> Self;
}

/// Key material [`ExternalizeKeyMaterial::externalize_keys`] moved out of a config, for the
/// caller to actually write to disk.
#[derive(Debug, Clone)]
pub struct GeneratedKeyMaterial {
    /// Path the caller should write `pem_bytes` to -- matches the path now embedded in the config
    /// that was passed through `externalize_keys`.
    pub path: PathBuf,
    /// PKCS8 PEM-encoded ed25519 private key bytes.
    pub pem_bytes: Vec<u8>,
}

/// Implemented by each transport's `ServerConfig` to move any inline (base64) key material it
/// carries out to PEM file(s) on disk -- for operators who want key material kept out of the
/// config file itself, e.g. to apply stricter file permissions to it independently.
///
/// Complements [`GenerateServerConfig`]: generation only ever produces in-memory/inline key
/// material and so needs no `Path` and can't fail; externalizing that material to files is a
/// distinct, later, fallible (re-parsing the inline key to re-encode it as PEM) step, and entirely
/// optional -- a config with inline key material is already complete and usable as-is.
pub trait ExternalizeKeyMaterial: Sized {
    /// Move this config's inline key material out to file(s) under `dir`, returning the updated
    /// config (now referencing the file paths in place of the inline key(s) it had) and the file
    /// contents the caller must write to actually persist them.
    fn externalize_keys(
        self,
        dir: &Path,
    ) -> Result<(Self, Vec<GeneratedKeyMaterial>), TransportError>;
}

/// Shared by every transport's [`ExternalizeKeyMaterial`] impl: move `identity_key` (if set) out
/// to a PEM file named `default_filename` under `dir`. No-op if `identity_key` is already unset
/// (there's no identity yet, or it's already file-backed).
fn externalize_identity(
    identity_key: &mut Option<String>,
    private_ed25519_identity_key_file: &mut Option<PathBuf>,
    dir: &Path,
    default_filename: &str,
) -> Result<Vec<GeneratedKeyMaterial>, TransportError> {
    let Some(base64_key) = identity_key.take() else {
        return Ok(Vec::new());
    };

    let source = ServerConfigSource::from_identity_base64(&base64_key)?;
    let path = dir.join(default_filename);
    let pem_bytes = source.to_pkcs8_pem_bytes()?;
    *private_ed25519_identity_key_file = Some(path.clone());

    Ok(vec![GeneratedKeyMaterial { path, pem_bytes }])
}
