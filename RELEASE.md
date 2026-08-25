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
