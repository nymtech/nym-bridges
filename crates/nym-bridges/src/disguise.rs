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

/// Rendezvous-hashing pick (highest `fnv1a(id_pubkey + host)` wins): stable under growth, since
/// appending a host never changes who wins between two hosts already in `pool`.
fn pick(pool: &[&str], id_pubkey: &str) -> String {
    pool.iter()
        .max_by_key(|host| fnv1a(&format!("{id_pubkey}{host}")))
        .expect("pool is non-empty")
        .to_string()
}

/// Stable per-`id_pubkey` pick from [`DISGUISE_HOSTS`], so a node's SNI survives repeated
/// `bridge-cfg` runs without a persisted field.
pub fn disguise_host(id_pubkey: &str) -> String {
    pick(DISGUISE_HOSTS, id_pubkey)
}

/// Every name a client holding any released descriptor might send as SNI: the legacy host, and
/// this node's pick under every size the pool has ever been (its prefixes, since it only grows).
pub fn historical_hosts(id_pubkey: &str) -> Vec<String> {
    let mut hosts: Vec<String> = (1..=DISGUISE_HOSTS.len())
        .map(|len| pick(&DISGUISE_HOSTS[..len], id_pubkey))
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    hosts.push(LEGACY_SHARED_HOST.to_string());
    hosts
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

    /// Growth only ever reassigns a pubkey *to* the new host, never between existing ones.
    #[test]
    fn disguise_host_growth_never_reshuffles_an_existing_pick() {
        let smaller_pool = &DISGUISE_HOSTS[..DISGUISE_HOSTS.len() - 1];
        let new_host = DISGUISE_HOSTS[DISGUISE_HOSTS.len() - 1];

        for i in 0u32..200 {
            let id_pubkey = format!("key-{i}");
            let before = pick(smaller_pool, &id_pubkey);
            let after = pick(DISGUISE_HOSTS, &id_pubkey);
            assert!(
                after == before || after == new_host,
                "key-{i}: {before} -> {after} on growth (reshuffled, not just reassigned to the new host)"
            );
        }
    }

    /// A pubkey's pre-growth pick stays recognised even after it's reassigned to a new host.
    #[test]
    fn historical_hosts_covers_every_pool_size_this_pubkey_has_ever_seen() {
        for i in 0u32..200 {
            let id_pubkey = format!("key-{i}");
            let hosts = historical_hosts(&id_pubkey);
            for len in 1..=DISGUISE_HOSTS.len() {
                let pick_at_that_size = pick(&DISGUISE_HOSTS[..len], &id_pubkey);
                assert!(
                    hosts.contains(&pick_at_that_size),
                    "key-{i}: historical_hosts is missing {pick_at_that_size:?}, this pubkey's pick under a {len}-entry pool"
                );
            }
        }
    }

    #[test]
    fn historical_hosts_includes_legacy_and_current() {
        let hosts = historical_hosts("gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=");
        assert!(hosts.iter().any(|h| h == LEGACY_SHARED_HOST));
        assert!(hosts.contains(&disguise_host(
            "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU="
        )));
    }
}
