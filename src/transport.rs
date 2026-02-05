use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub mod quic;
pub mod tls;

// ====================================[ Shared Client Options ]====================================

/// Client-side transport options shared across all transport types (QUIC, TLS).
///
/// This struct contains the common configuration for establishing client connections
/// to a bridge server, including addressing, SNI configuration, and identity verification.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ClientOptions {
    /// Address describing the remote transport server. This is a vec to support multiple addresses
    /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
    /// as the key material should not be used across multiple instances.
    ///
    /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
    pub addresses: Vec<SocketAddr>,

    /// Override hostname used for certificate verification
    pub host: Option<String>,

    /// If set, this value is sent as SNI regardless of `host` or identity key.
    /// The server's certificate is still verified against the identity key, not this SNI.
    #[serde(default)]
    pub sni_override: Option<String>,

    /// Use identity public key to verify server self signed certificate (base64 encoded)
    pub id_pubkey: String,
}

impl ClientOptions {
    /// Returns the SNI to send in ClientHello.
    /// Priority: sni_override > host > IP address of first address
    pub fn effective_sni(&self) -> String {
        self.sni_override
            .clone()
            .or_else(|| self.host.clone())
            .unwrap_or_else(|| self.addresses[0].ip().to_string())
    }

    /// Returns the alt_names for certificate verification.
    pub fn alt_names_for_verification(&self) -> Option<Vec<String>> {
        let mut alt_names_vec = Vec::new();
        if let Some(ref h) = self.host {
            alt_names_vec.push(h.clone());
        }
        if let Some(ref sni) = self.sni_override
            && !alt_names_vec.contains(sni)
        {
            alt_names_vec.push(sni.clone());
        }
        if alt_names_vec.is_empty() {
            None
        } else {
            Some(alt_names_vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_options(host: Option<&str>, sni_override: Option<&str>) -> ClientOptions {
        ClientOptions {
            addresses: vec!["192.168.1.1:443".parse().unwrap()],
            host: host.map(String::from),
            sni_override: sni_override.map(String::from),
            id_pubkey: "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=".into(),
        }
    }

    #[test]
    fn effective_sni_uses_sni_override_when_set() {
        let opts = make_options(Some("host.example.com"), Some("example.com"));
        assert_eq!(opts.effective_sni(), "example.com");
    }

    #[test]
    fn effective_sni_uses_host_when_no_override() {
        let opts = make_options(Some("host.example.com"), None);
        assert_eq!(opts.effective_sni(), "host.example.com");
    }

    #[test]
    fn effective_sni_uses_ip_when_no_host_or_override() {
        let opts = make_options(None, None);
        assert_eq!(opts.effective_sni(), "192.168.1.1");
    }

    #[test]
    fn alt_names_includes_both_host_and_sni_override() {
        let opts = make_options(Some("host.example.com"), Some("example.com"));
        let alt_names = opts.alt_names_for_verification().unwrap();
        assert_eq!(alt_names.len(), 2);
        assert!(alt_names.contains(&"host.example.com".to_string()));
        assert!(alt_names.contains(&"example.com".to_string()));
    }

    #[test]
    fn alt_names_includes_only_host_when_no_override() {
        let opts = make_options(Some("host.example.com"), None);
        let alt_names = opts.alt_names_for_verification().unwrap();
        assert_eq!(alt_names.len(), 1);
        assert!(alt_names.contains(&"host.example.com".to_string()));
    }

    #[test]
    fn alt_names_includes_only_override_when_no_host() {
        let opts = make_options(None, Some("example.com"));
        let alt_names = opts.alt_names_for_verification().unwrap();
        assert_eq!(alt_names.len(), 1);
        assert!(alt_names.contains(&"example.com".to_string()));
    }

    #[test]
    fn alt_names_is_none_when_neither_set() {
        let opts = make_options(None, None);
        assert!(opts.alt_names_for_verification().is_none());
    }

    #[test]
    fn alt_names_deduplicates_when_host_equals_override() {
        let opts = make_options(Some("example.com"), Some("example.com"));
        let alt_names = opts.alt_names_for_verification().unwrap();
        assert_eq!(alt_names.len(), 1);
        assert!(alt_names.contains(&"example.com".to_string()));
    }
}
