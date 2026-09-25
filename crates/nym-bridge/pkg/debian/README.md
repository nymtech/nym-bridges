# Nym Bridge Debian Package

## Installation

### Download and Install

```sh
# Download the package
VERSION="<release-version>"   # example: 0.2.0
REVISION="1"
ARCH="amd64"
wget "https://github.com/nymtech/nym-bridges/releases/download/bridge-binaries-v${VERSION}/nym-bridge_${VERSION}-${REVISION}_${ARCH}.deb"


# Install the package
sudo dpkg -i "nym-bridge_${VERSION}-${REVISION}_${ARCH}.deb"
sudo apt-get install -f

# Start service
sudo systemctl enable nym-bridge
sudo systemctl start nym-bridge
```

### Building from Source

```sh
# From repository root
cargo deb -p nym-bridge

# Pick the newest built nym-bridge package artifact
DEB="$(ls -1t target/debian/nym-bridge_*_amd64.deb | head -n1)"

# Check build artifacts
lintian "$DEB"

# Inspect package contents
mkdir debdir
dpkg-deb -R "$DEB" debdir
tree debdir
```

## Package Contents

- **nym-bridge**: Main daemon binary (runs as `nym` user)
- **bridge-cfg**: Configuration tool  
- **systemd service**: `nym-bridge.service`
- **Auto-configuration**: Creates `nym` user and config
- **Security**: Runs with restricted permissions by default

## Service Management

```sh
# Control service
sudo systemctl start nym-bridge
sudo systemctl stop nym-bridge
sudo systemctl restart nym-bridge
sudo systemctl enable nym-bridge
sudo systemctl disable nym-bridge

# Check status
sudo systemctl status nym-bridge

# View logs
sudo journalctl -u nym-bridge -f
```

## Configuration

```sh
# Edit configuration
sudo nano /etc/nym/bridges.toml

# Regenerate config (if network conditions changed, this will re-detect IPs)
sudo bridge-cfg --gen -i /etc/nym/bridges.toml -o /etc/nym/bridges.toml

# Restart service
sudo systemctl restart nym-bridge
```

### Firewall Rules

Firewall ports are derived from the `listen` addresses of the transports in `/etc/nym/bridges.toml`
(`quic_plain` → UDP, `tls_plain` / `ssh_plain` → TCP). They are opened each time the service starts
and closed when it stops, so after changing a listen port a `systemctl restart nym-bridge` is all
that is required; rules for ports that are no longer configured are removed automatically.

Supported firewall managers are ufw (via a `nym-bridge` application profile), firewalld and
iptables. With nftables, the required rules are printed to the service log for manual setup.

```sh
# Show the ports the current config listens on
sudo nym-bridge --config /etc/nym/bridges.toml --print-ports

# Apply / remove the rules manually
sudo /usr/lib/nym-bridge/firewall-sync open
sudo /usr/lib/nym-bridge/firewall-sync close
```

### Refreshing IP Configuration

Every time the service starts it runs `bridge-cfg --refresh`, which regenerates
`client_bridge_params.json` from `/etc/nym/bridges.toml`. How the public IPs are handled depends
on `public_ips_source` in the bridge config:

- `"auto"` (default for newly generated configs): `public_ips` and `forward.address` are taken
  from the nym-node config (`host.public_ips`, located via `node_config_path`). Detection over the
  internet is only used if the node config has no public IPs.
- `"static"` (assumed for configs without the field): `public_ips` and `forward.address` are never
  modified. Use this if you set the IPs by hand.

Files are only rewritten when their contents change. So after an IP change (update the nym-node
config first, if it doesn't pick the change up itself), a restart is all that is needed:

```sh
# Preview what a refresh would change
sudo bridge-cfg --refresh -i /etc/nym/bridges.toml --dry-run

# Apply it (the service also does this on every start)
sudo systemctl restart nym-bridge
```

To switch an existing config to follow the nym-node config, add the following to the top level of
`/etc/nym/bridges.toml` (above `[forward]`):

```toml
public_ips_source = "auto"
node_config_path = "/root/.nym/nym-nodes/default-nym-node/config/config.toml"
```

### Security: File Permissions

The service runs as the unprivileged `nym` user, which needs to read, but never modify, its config
and keys. The package enforces this layout:

| Path | Owner | Mode |
|---|---|---|
| `/etc/nym/bridges.toml` | `root:nym` | `640` |
| `/etc/nym/keys/` | `root:nym` | `750` |
| `/etc/nym/keys/*` | `root:nym` | `640` |

It is applied at install time and again every time the service starts, so files created by
running `sudo bridge-cfg --gen` manually (which are created root-only, mode `600`) are fixed up
automatically on the next `systemctl restart nym-bridge`. Key files referenced from outside
`/etc/nym/keys/` are left untouched and must be made readable by the `nym` group manually. Do not
tighten these modes further (e.g. `chmod 600`) or the service will be unable to read them.

```sh
# Re-apply the permissions without restarting
sudo /usr/lib/nym-bridge/fix-permissions

# Verify permissions
ls -la /etc/nym/bridges.toml /etc/nym/keys/
```

**Important:** Never commit config files or keys to version control or share them publicly. They contain sensitive cryptographic material.

## Running as Different User

The service runs as the `nym` user by default for security. If you need to run as a different user (e.g., root), you can modify the service:

```sh
# Create systemd override
sudo systemctl edit nym-bridge

# Add these lines:
[Service]
User=root
Group=root

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart nym-bridge
```

**Warning**: Running as root reduces security. Only do this if you have a specific requirement.

## Integration with nym-node

If you're running both `nym-node` and `nym-bridge` on the same machine:

```sh
# Check both services
ps aux | grep -E "(nym-node|nym-bridge)" | grep -v grep

# Verify ports
sudo netstat -tulpn | grep -E "(51822|4443)"

# Test traffic forwarding
telnet localhost 51822  # nym-node WireGuard
telnet localhost 4443   # nym-bridge QUIC
```

## Testing

### Run Tests

```sh
# Run all bridge-cfg tests
cd /path/to/nym-bridges
cargo test -p bridge-cfg

# Run specific malformed config tests
cargo test -p bridge-cfg test_malformed_configs

# Run integrated config tests
cargo test -p bridge-cfg test_integrated_config_parsing
```

### Test Configuration

```sh
# Test configuration generation (dry run)
bridge-cfg --gen --dry-run

# View effective configuration
sudo cat /etc/nym/bridges.toml
```

## Troubleshooting

### Configuration Issues

```sh
# Regenerate from nym-node config
sudo bridge-cfg --gen

# View effective configuration
sudo cat /etc/nym/bridges.toml

# Check service logs for errors
sudo journalctl -u nym-bridge -n 50
```

## Uninstallation

```sh
# Remove package (keeps config)
sudo apt remove nym-bridge

# Purge package (removes config)
sudo apt purge nym-bridge

# Clean up user and directories
sudo userdel -r nym
sudo rm -rf /etc/nym/ /var/lib/nym/
```
