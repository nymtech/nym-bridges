
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added new ssh transport based on russh (https://github.com/nymtech/nym-bridges/pull/53)
- dependency version patches (https://github.com/nymtech/nym-bridges/pull/61)
- TLS transport usable from a unified BridgeConn object (https://github.com/nymtech/nym-bridges/pull/60)
- `utoipa` support for integration against nym-sdk and nym-smoldvpn

### Changed

- Changed license version from GPL_v3 to dual MIT & APACHE-2.0 (https://github.com/nymtech/nym-bridges/pull/63)
- attempt connection open to all addresses provided in a ClientConfig using happy eyeballs (https://github.com/nymtech/nym-bridges/pull/64)
- removed filter to ipv4 only from quic_plain transport (https://github.com/nymtech/nym-bridges/pull/64)

### Fixed

- Ensure `uniffi` alignment wit cargo-swift (https://github.com/nymtech/nym-bridges/pull/54)
- Library generation and naming for uniffi integration (https://github.com/nymtech/nym-bridges/pull/62)


## [0.2.0] Initial published version