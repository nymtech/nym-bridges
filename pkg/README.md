# Packaging

## Debian

Build Debian package for the `nym-bridge` as a service.

### Quick Build

```sh
# From repository root
cargo deb -p nym-bridge
```

### Check Build Artifacts

```sh
# Pick the newest built nym-bridge package artifact
DEB="$(ls -1t target/debian/nym-bridge_*_amd64.deb | head -n1)"

# Check Debian best practices
lintian "$DEB"

# Inspect package contents
mkdir -p debdir
dpkg-deb -R "$DEB" debdir
tree debdir
```

### Installation and Usage

For complete installation, configuration, and troubleshooting instructions, see:

**[debian/README.md](debian/README.md)**

This includes:
- Installation instructions
- Service management
- Configuration options
- Running as different user
- Integration with nym-node
- Testing and validation
- Uninstallation steps
