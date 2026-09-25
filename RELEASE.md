# Release process

This workspace publishes two crates to crates.io — `nym-bridges-types` and `nym-bridges`
(`bridge-cfg`, `bridge-tools`, and `nym-bridge` are all `publish = false`). All five crates
share a single version via `workspace.package.version` in the root [`Cargo.toml`](./Cargo.toml).

`nym-bridges` depends on `nym-bridges-types` as a **path dependency with an explicit version
requirement** (see `crates/nym-bridges/Cargo.toml`). `cargo publish` resolves that requirement
against crates.io, not the local path, so `nym-bridges-types` must already be live on crates.io
at the new version before `nym-bridges` can be published against it. Publishing out of order
fails immediately with something like:

```
error: failed to prepare local package for uploading
Caused by:
  failed to select a version for the requirement `nym-bridges-types = "^X.Y.Z"`
  candidate versions found which didn't match: ...
```

## Steps

1. **Update the changelog.** Move everything under `## [Unreleased]` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (this repo follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)),
   leaving a fresh empty `## [Unreleased]` above it. Fill in any PRs merged since the last
   release that aren't reflected there yet — a quick check is
   `git log <last-tag>..HEAD --oneline`.

2. **Bump the version.** Update `workspace.package.version` in the root `Cargo.toml`, and update
   the matching version requirement on the `nym-bridges-types` dependency in
   `crates/nym-bridges/Cargo.toml` to the same value. Run a build to regenerate `Cargo.lock`:

   ```sh
   cargo build --workspace --all-targets --all-features
   ```

3. **Verify.**

   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-targets --all-features
   cargo test --doc --workspace --all-features
   ```

4. **Dry-run the publish** for both publishable crates, in dependency order:

   ```sh
   cargo publish --dry-run -p nym-bridges-types
   cargo publish --dry-run -p nym-bridges
   ```

   The `nym-bridges` dry run is expected to fail on the version-resolution error above until
   `nym-bridges-types` is actually live on crates.io (step 6) — that's normal, not a sign
   something is broken.

5. **Commit and tag.**

   ```sh
   git add Cargo.toml Cargo.lock crates/nym-bridges/Cargo.toml CHANGELOG.md
   git commit -m "Release vX.Y.Z"
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```

6. **Publish `nym-bridges-types` first**, then wait for it to show up in the crates.io index
   before publishing `nym-bridges` (usually well under a minute, but `cargo publish -p
   nym-bridges` will fail with the same version-resolution error if you're too fast):

   ```sh
   cargo publish -p nym-bridges-types
   cargo publish -p nym-bridges
   ```

7. **Bump to the next dev version.** After a release this repo bumps `workspace.package.version`
   again right away (e.g. `X.Y.(Z+1)-rc.1`) so `main` never sits at a version that's already
   published. Commit that as a separate follow-up commit.

## Binary artifacts (optional)

`.github/workflows/build-and-package.yml` builds `nym-bridge` and `bridge-cfg` release binaries
plus a `.deb` package and uploads them as a GitHub Actions artifact (30-day retention). It's not
triggered by tags — only manually (`workflow_dispatch`) or nightly on a schedule — so if binaries
are wanted for a given release, trigger it manually against the release tag/commit and attach the
artifacts to a GitHub Release by hand.

GitHub attaches `Source code (zip)` / `Source code (tar.gz)` archives of the tag to every release
automatically; only the binaries and `.deb` need to be uploaded.

### Building them by hand

Build from a checkout of the release tag, not `main` — the `.deb` version comes from
`workspace.package.version`, so building after the step 7 bump produces e.g. a `0.2.3~rc.1`
package.

```sh
git checkout vX.Y.Z
cargo build --release --locked -p nym-bridge -p bridge-cfg
cargo deb -p nym-bridge --no-build
```

The output is `target/release/{nym-bridge,bridge-cfg}` and
`target/debian/nym-bridge_X.Y.Z-1_amd64.deb`.

- **`--locked`** builds exactly what `Cargo.lock` pins, and fails rather than silently resolving
  different dependency versions than were tested.
- **Build `bridge-cfg` explicitly, then `cargo deb --no-build`.** `cargo deb` only builds the
  `nym-bridge` package; `bridge-cfg` is a separate crate that the deb metadata in
  `crates/nym-bridge/Cargo.toml` picks up as an asset from `target/release/bridge-cfg`. Without the
  explicit build that file is either missing (packaging fails) or stale from an earlier build
  (packaging silently ships an old `bridge-cfg`).
- **glibc floor.** The binaries link dynamically against glibc, and cargo-deb records the
  requirement (e.g. `Depends: libc6 (>= 2.35)`). The build host's glibc sets the oldest distro the
  release runs on — CI's `ubuntu-22.04` means glibc 2.35, which excludes Debian 11 and Ubuntu 20.04.
  Build on an older image, or use `--target x86_64-unknown-linux-musl` for a static binary, if
  those need to be supported.
- **Stripping.** cargo-deb strips the binaries it packages, but `target/release/*` still carries
  symbols. Run `strip` on them before attaching the raw binaries to a release.

Before uploading, sanity-check the package:

```sh
dpkg-deb -I target/debian/nym-bridge_*.deb   # version, Depends, maintainer scripts
dpkg-deb -c target/debian/nym-bridge_*.deb   # both binaries + pkg/ helpers present
lintian target/debian/nym-bridge_*.deb       # optional; apt install lintian
```
