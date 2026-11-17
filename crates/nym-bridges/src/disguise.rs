//! Per-node disguise names, shared between the client-facing config (`config.rs`, the SNI a
//! client sends) and the server's TLS/QUIC certificates (`transport::tls::certs`, the name(s)
//! a server is willing to present). Names are append-only: a host used by any released
//! `bridge-cfg` build stays recognised forever, so a client that hasn't refreshed its config
//! keeps connecting.

/// The single shared host every descriptor used before per-node disguise names existed.
pub const LEGACY_SHARED_HOST: &str = "netdna.bootstrapcdn.com";

/// SNI candidates, chosen so blocking one costs the censor collateral damage.
const DISGUISE_HOSTS: &[&str] = &[
    "www.bing.com",
    "www.microsoft.com",
    "m.media-amazon.com",
    "www.apple.com",
    "www.samsung.com",
];

/// Stable per-`id_pubkey` pick from [`DISGUISE_HOSTS`], so a node's SNI survives repeated
/// `bridge-cfg` runs without a persisted field.
pub fn disguise_host(id_pubkey: &str) -> String {
    // FNV-1a -- order-sensitive, not a security boundary, just needs to spread picks.
    let hash = id_pubkey.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    });
    DISGUISE_HOSTS[(hash % DISGUISE_HOSTS.len() as u64) as usize].to_string()
}

/// Every name a client holding *any* released descriptor for `id_pubkey` might send as SNI:
/// the legacy shared host, and this node's current disguise host. Append-only - a future
/// disguise pool adds a new entry here, it never removes one.
pub fn historical_hosts(id_pubkey: &str) -> Vec<String> {
    vec![LEGACY_SHARED_HOST.to_string(), disguise_host(id_pubkey)]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn disguise_host_is_stable_and_spreads_across_pubkeys() {
        let a = "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=";
        let b = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=";

        assert_eq!(disguise_host(a), disguise_host(a));
        assert_ne!(disguise_host(a), disguise_host(b));
    }

    #[test]
    fn disguise_host_covers_every_pool_entry() {
        use std::collections::HashSet;

        let seen: HashSet<_> = (0u32..200)
            .map(|i| disguise_host(&format!("key-{i}")))
            .collect();

        assert_eq!(seen.len(), DISGUISE_HOSTS.len());
    }

    #[test]
    fn historical_hosts_includes_legacy_and_current() {
        let hosts = historical_hosts("gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=");
        assert!(hosts.contains(&LEGACY_SHARED_HOST.to_string()));
        assert!(hosts.contains(&disguise_host(
            "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU="
        )));
    }
}
