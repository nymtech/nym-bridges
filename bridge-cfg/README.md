# Nym Bridge Configuration Tool

The initial [bridge transport runner](../nym-bridge/) is designed to use generated ED25519 keys to
sign certificates guaranteeing the authenticity and security of the established TLS handshakes.
Additionally the runner is designed to proxy traffic received in successful connections to a local
service, for the initial deployment alongside a `nym-node` this is the wireguard service used for
DVPN connections. 

In order to accomplish this the `bridge-cfg` tool is designed to

- Store listener config in the local node config location
  - (+) Generate keys for transport usage
  - (+) Populate or adjust configuration to match fields in the `nym-node` config
- Parse the `nym-node` config for relevant info
	- Public IP address
	- Wireguard listen port
  - (+) Add a field with a path to the bridge client parameters
- Generate a json file with the relevant bridge parameters required for client connections.

Example layout for bridge configuration stored alongside `nym-node` config.

```
$HOME/.nym/nym-nodes/default-nym-node/
├── config              
│   ├── (+) bridges.toml
│   ├── (+) client_bridge_params.json
│   └── (Δ) config.toml
└──  data                
    ├── aes128ctr_auth_ack
    ├── aes128ctr_ipr_ack
    ├── …
    ├── (+) ed25519_bridge_identity.pem
    ├── …
```

## Usage

```txt
Usage: bridge-cfg [OPTIONS]

Options:
  -d, --dir <NODE_CONFIG_DIR>         Provide a path to the `nym-node` configuration that will be used to populate the bridge config
      --id <ID>                       Node ID used for the nym-node. This is used to construct a default path using a custom ID to the `nym-node` configuration that will be used to populate the bridge config [default: default-nym-node]
  -i, --in <BRIDGE_CONFIG_PATH_IN>    Provide a path to the input location for a populated bridge configuration. If none is provided, default values will be used for required fields
  -o, --out <BRIDGE_CONFIG_PATH_OUT>  Provide a path to the output location for the populated bridge configuration. If none is provided, the default location for nym configuration files is used
      --dry-run                       Print the resulting bridge config file wih diff changes without writing to the output path
  -h, --help                          Print help
```

### Example

We can run a dry run on a test `nym-node` configuration to generate a compatible configuration
that can be used for the [`nym-bridge`](../nym-bridge/) runner.

`bridge-cfg -i ./bridges.template.toml -d bridge-cfg/test --dry-run`

* `-i ./bridges.template.toml` - Use the default `nym-bridge` configuration as an existing bridge configuration. 
* `-d bridge-cfg/test` - Treat the `bridge-cfg/test` directory as our configuration directory for finding the existing `nym-node` config and for writing the output nym-bridge config.
* `--dry-run` - Print the resulting `nym-bridge` config with indications of the changes as compared to the original WITHOUT writing it to file. 

This will result in the following output:

```diff
"bridge-cfg/test/bridges.toml":
  # Nym Bridge Gateway Runner Configuration
...

  # Target address where client traffic will be forwarded.
  #
  # If running in parallel with `nym-node` this should match with your public IP and announced wireguard port.
- address = "[::1]:51822"
+ address = "1.1.1.1:51822"
  
  [[transports]]
  transport_type = "quic_plain"
...
  
  # Path to file containing PEM encoded ed25519 identity private key, for use in ED25519 based self signed certs
- private_ed25519_identity_key_file = '/etc/nym/default-nym-node/bridges/ed25519_identity'
+ private_ed25519_identity_key_file = "/home/nym/.nym/nym-nodes/default-nym-node/data/ed25519_identity"
  
...

  # Path to file containing PEM encoded ed25519 identity private key, for use in ED25519 based self signed certs
- private_ed25519_identity_key_file = '/etc/nym/default-nym-node/bridges/ed25519_identity'
+ private_ed25519_identity_key_file = "/home/nym/.nym/nym-nodes/default-nym-node/data/ed25519_identity"
  
...
```

## Future Work

In the future this tool is planned as a means of generating and validating configuration for the
multiple bridge types that we intend to support and ensuring compatibility with a running `nym-node`. 


Currently the default Bridges config is taken from the repo root and included at compile time. In the
future this may change such that a default config is places in a default location in the filesystem
rather than using a build directive to add it to the binary. 