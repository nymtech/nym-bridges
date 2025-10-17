# Nym Bridge Debian Package

## Installation

### Download and Install

```sh
# Download the package
wget https://github.com/nymtech/nym-bridges/releases/download/bridge-binaries-v0.1.2/nym-bridge_0.1.0-2_amd64.deb

# Install the package
sudo dpkg -i nym-bridge_0.1.0-2_amd64.deb
sudo apt-get install -f

# Start service
sudo systemctl enable nym-bridge
sudo systemctl start nym-bridge
```

### Building from Source

```sh
# From repository root
cargo deb

# Check build artifacts
lintian target/debian/nym-bridge_0.1.0-1_amd64.deb

# Inspect package contents
mkdir debdir
dpkg-deb -R target/debian/nym-bridge_0.1.0-1_amd64.deb debdir
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

### Refreshing IP Configuration

If your server's public IP addresses change (e.g., after network reconfiguration), you can refresh the configuration:

```sh
# Re-detect public IPs and update config (preserves existing keys)
sudo bridge-cfg --gen -i /etc/nym/bridges.toml -o /etc/nym/bridges.toml

# Verify the changes before restarting
sudo cat /etc/nym/bridges.toml | grep public_ips

# Restart the service
sudo systemctl restart nym-bridge
```

### Security: File Permissions

The package automatically sets secure file permissions during installation. For production deployments, consider further restricting access:

```sh
# Restrict config to owner only (more secure)
sudo chmod 600 /etc/nym/bridges.toml

# Ensure keys directory is protected
sudo chmod 700 /etc/nym/keys
sudo chmod 600 /etc/nym/keys/*

# Verify permissions
ls -la /etc/nym/
ls -la /etc/nym/keys/
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
