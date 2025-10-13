# Nym Bridge Debian Package

## Installation

### Download and Install

# Download the package
wget https://github.com/nymtech/nym-bridges/releases/download/bridge-binaries-v0.1.0/nym-bridge_0.1.0-1_amd64.deb

# Install the package
sudo dpkg -i nym-bridge_0.1.0-1_amd64.deb
sudo apt-get install -f

# Start service
sudo systemctl enable nym-bridge
sudo systemctl start nym-bridge
```

### Building from Source


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


# Edit configuration
sudo nano /etc/nym/bridges.toml

# Regenerate config
sudo bridge-cfg --gen

# Restart service
sudo systemctl restart nym-bridge
```

## Running as Different User

The service runs as the `nym` user by default for security. If you need to run as a different user (e.g., root), you can modify the service:

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

# Run all bridge-cfg tests
cd /path/to/nym-bridges
cargo test -p bridge-cfg

# Run specific malformed config tests
cargo test -p bridge-cfg test_malformed_configs

# Run integrated config tests
cargo test -p bridge-cfg test_integrated_config_parsing
```

### Test Configuration


# Test configuration generation (dry run)
bridge-cfg --gen --dry-run

# Validate existing configuration
bridge-cfg --validate /etc/nym/bridges.toml
```


### Configuration Issues

# Check config syntax
sudo bridge-cfg --validate /etc/nym/bridges.toml

# Regenerate from nym-node config
sudo bridge-cfg --gen

# View effective configuration
sudo cat /etc/nym/bridges.toml
```

## Uninstallation


# Remove package (keeps config)
sudo apt remove nym-bridge

# Purge package (removes config)
sudo apt purge nym-bridge

# Clean up user and directories
sudo userdel -r nym
sudo rm -rf /etc/nym/ /var/lib/nym/
```
