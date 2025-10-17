# Packaging

## Debian

Build Debian package for the `nym-bridge` as a service.

### Quick Build


# From repository root
cargo deb

### Check Build Artifacts


# Check Debian best practices
lintian target/debian/nym-bridge_0.1.0-2_amd64.deb

# Inspect package contents
mkdir debdir
dpkg-deb -R target/debian/nym-bridge_0.1.0-2_amd64.deb debdir
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
