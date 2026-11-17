//! Per-node disguise names, shared between the client descriptor (`config.rs`) and the server's
//! certificates (`transport::tls::certs`). Append-only, so an un-refreshed client keeps working.

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

// FNV-1a -- order-sensitive, not a security boundary, just needs to spread picks.
fn fnv1a(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    })
}

/// Stable per-`id_pubkey` pick from [`DISGUISE_HOSTS`], so a node's SNI survives repeated
/// `bridge-cfg` runs without a persisted field. Picks by rendezvous hashing (highest
/// `fnv1a(id_pubkey + host)` wins) rather than `hash % len()`, so appending a host to the pool
/// only ever reassigns pubkeys *to* the new entry - it never reshuffles who gets an existing
/// one, which `% len()` would.
pub fn disguise_host(id_pubkey: &str) -> String {
    DISGUISE_HOSTS
        .iter()
        .max_by_key(|host| fnv1a(&format!("{id_pubkey}{host}")))
        .expect("DISGUISE_HOSTS is non-empty")
        .to_string()
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

    /// Appending a host to the pool must only ever reassign pubkeys *to* the new entry, never
    /// reshuffle an assignment between two pre-existing entries - otherwise a node that upgrades
    /// after such a change would stop matching clients still holding its old descriptor.
    #[test]
    fn disguise_host_growth_never_reshuffles_an_existing_pick() {
        let smaller_pool = &DISGUISE_HOSTS[..DISGUISE_HOSTS.len() - 1];
        let grown_pool = DISGUISE_HOSTS;
        let new_host = DISGUISE_HOSTS[DISGUISE_HOSTS.len() - 1];

        fn pick<'a>(pool: &[&'a str], id_pubkey: &str) -> &'a str {
            pool.iter()
                .max_by_key(|host| fnv1a(&format!("{id_pubkey}{host}")))
                .copied()
                .unwrap()
        }

        for i in 0u32..200 {
            let id_pubkey = format!("key-{i}");
            let before = pick(smaller_pool, &id_pubkey);
            let after = pick(grown_pool, &id_pubkey);
            assert!(
                after == before || after == new_host,
                "key-{i}: {before} -> {after} on growth (reshuffled, not just reassigned to the new host)"
            );
        }
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
