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
│   └── (Δ) config.toml
└──  data                
    ├── aes128ctr_auth_ack
    ├── aes128ctr_ipr_ack
    ├── …

/etc/nym/
├── keys 
│   └── (+) ed25519_bridge_identity.pem
├── (+) client_bridge_params.json
└── (+) bridges.toml
```

## Usage

```txt
Usage: bridge-cfg [OPTIONS]

Options:
  -n, --node-config <NODE_CONFIG>     Provide a path to the `nym-node` configuration that will be used to populate the node config. If none is provided the default configuration path for the default `nym-node` ID will be assumed, unless an alternate node ID is provided using the `--id` flag. (default: `$HOME/.nym/nym-nodes/$NYMNODE_ID/config/`)
      --id <ID>                       Node ID used for the nym-node. This is used to construct a default path using a custom ID to the `nym-node` configuration that will be used to populate the bridge config [default: default-nym-node]
  -d, --dir <OUT_DIR>                 Provide a path to the output directory location for the populated bridge configuration and supporting materials (i.e key(s)) [default: /etc/nym]
  -i, --in <BRIDGE_CONFIG_PATH_IN>    Provide a path to the input location for a populated bridge configuration. If none is provided, default values will be used for required fields
  -o, --out <BRIDGE_CONFIG_PATH_OUT>  Provide a path to the output location for the populated bridge configuration. If none is provided, the default location for nym configuration files is used
      --gen                           If key material is either not specified, or files do not exist at the specified path generate the key material
      --allow-overwrite               DANGER -- Re-generate transport key material, even if it already exists. Overwritten keys will not be recoverable unless saved elsewhere
      --dry-run                       Print the resulting config files wih diff info without persisting the changes
  -h, --help                          Print help (see more with '--help')
```

### Example

We can run a dry run on a test `nym-node` configuration to generate a compatible configuration
that can be used for the [`nym-bridge`](../nym-bridge/) runner.

`bridge-cfg --gen -n bridge-cfg/test/config.toml -d bridge-cfg/test --dry-run`

* `--gen` - Generate key material if it doesn't already exist. If this is not specified the tool assumes key material already exists, returning an error if the pre-existing key material is not found. 
* `-d bridge-cfg/test` - Treat the `bridge-cfg/test` directory as our output directory for generated files.
* `--dry-run` - Print the resulting `nym-bridge` config with indications of the changes as compared to the original WITHOUT writing it to file. 
* `-n bridge-cfg/test/config.toml` - use the example Nym node config at `bridge-cfg/test/config.toml`. If not specified the configuration tool will first check the default nym-node config path, falling back to defaults it it does not find
the config in the expected location.

This will result in the following output:

```diff
 > "bridge-cfg/test/config.toml":
...
- bridge_client_params = '/home/nym/.nym/nym-nodes/default-nym-node/config/client_bridge_params.json'
+ bridge_client_params = "bridge-cfg/test/client_bridge_params.json
...

 > "bridge-cfg/test/client_bridge_params.json":
+ {"version":"0.0.0","transports":[{"transport_type":"quic_plain","args":{"addresses":["192.168.0.1:4443","[fe80::1]:4443"],"host":null,"id_pubkey":"lmv/PMS1MQ0G71hUljt6BWpLhvBK1DyiozEF7Ux/HPo="}}]}

 > "bridge-cfg/test/bridges.toml":
  # Nym Bridge Gateway Runner Configuration
...
- client_params_path = "/etc/nym/default-nym-node/client_bridge_params.json"
+ client_params_path = "bridge-cfg/test/client_bridge_params.json"
...

  # Target address where client traffic will be forwarded.
  #
  # If running in parallel with `nym-node` this should match with your public IP and announced wireguard port.
- address = "[::1]:51822"
+ address = "1.1.1.1:51822"
  
  [[transports]]
  transport_type = "quic_plain"
  
  [transports.args]
  # Enable stateless retries
  stateless_retry = false
  
  # (UDP) Socket address to listen on
  listen = "[::]:4443"
+ private_ed25519_identity_key_file = "bridge-cfg/test/keys/ed25519_bridge_identity.pem"
...
```

## Future Work

In the future this tool is planned as a means of generating and validating configuration for the
multiple bridge types that we intend to support and ensuring compatibility with a running `nym-node`. 


Currently the default Bridges config is taken from the repo root and included at compile time. In the
future this may change such that a default config is places in a default location in the filesystem
rather than using a build directive to add it to the binary. 