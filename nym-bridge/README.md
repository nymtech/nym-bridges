# Nym Bridge Runner



The nym-bridge binary runs the server side listener for the transports defined by the bridge
configuration. The binary can be built using:

```sh
cargo build --release -p nym-bridge -p bridge-cfg

# sudo cp target/release/nym-bridge /usr/local/bin/
```

#### Configure

The [`bridge-cfg`](../bridge-cfg/) tool is provided to assist with key generation and configuration
management -- for more details on automatic configuration see
[`bridge-cfg/README.md`](../bridge-cfg/README.md).

This tool assumes that the `nym-bridge` is going to be run alongside a `nym-node`

```sh
# Try a dry run to preview the configuration changes
bridge-cfg -d "$HOME/.nym/nym-nodes/default-nym-node/config/" --dry-run

# Allow configuration changes to be persisted
bridge-cfg -d "$HOME/.nym/nym-nodes/default-nym-node/config/"
```

#### Using Systemd

A systemd service file is provided to help run the nym-bridge as a daemon

```sh
# (make any modifications to the service file)

sudo cp nym-bridge.service /etc/systemd/system/
sudo systemctl enable nym-bridge
sudo systemctl start nym-bridge
```

<details>
<summary>Example nym-bridge systemd service file</summary>

```toml
[Unit]
Description=nym-bridge daemon

# Make sure the network is online before this starts
After=NetworkManager.service systemd-resolved.service nym-node.service

# Set a limit to the rate / number of restarts to prevent fail busy loop
# in case of misconfiguration or something
StartLimitBurst=5
StartLimitIntervalSec=30

[Service]
# User=<USER>
# Group=<USER>
# Type=simple
LimitNOFile=65536
ExecStart=/usr/local/bin/nym-bridge

Restart=on-abnormal
RestartSec=2

[Install]
WantedBy=multi-user.target
```

</details>

The nym-bridge binary (and the default systemd service file) assumes that the bridge configuration
file is in a default location (/etc/nym/default-nym-node/bridges.toml), so if the path of the bridge
configuration is not the default location, the systemd service can be modified to accommodate it.

```diff
[Service]
LimitNOFile=65536
- ExecStart=/usr/local/bin/nym-bridge
+ ExecStart=/usr/local/bin/nym-bridge -c <path to bridge config file>
```

#### Changes to the Nym Node

The nym node requires minimal changes. All we need it to do (for now) is to serve the client
parameters at a new endpoint in the self-described API.

This requires the changes in https://github.com/nymtech/nym/pull/6035/. While these changes are
implemented off of develop, they can be pretty easily cherrypicked back to feta. Also they will be
merged and squashed to a single commit ASAP.

So for now a manual build of the nym-node is required, however we can easily create a patch release
(and build) on feta that includes this change and it will be included in the next major release.


## Full Manual Setup Steps

- [ ] Nym Bridge Configuration
	- [ ] Generate keys
	- [ ] Write configuration file
- [ ] Create the associated client parameter file
- [ ] Add UFW exception(s)

If running alongside a `nym-node`
- [ ] Add the field to Nym-Node configuration for the path to the client bridge parameter file


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


#### 1) Key Generation

Generating Keys - The current transports (Quic and TLS – although we are only supporting Quic in the
client initially) both require an ED25519 key to secure the bridge transport connection. The key
needs to be either base64 encoded in the identity_key field in the configuration OR written in pkcs8
PEM format wih the path provided in the `private_ed25519_identity_key_file` field of the
configuration.

```sh
sudo apt-get install openssl

# Generate the ed25519 private key
openssl genpkey -algorithm Ed25519 -out private_key.pem
mv private_key.pem /home/nym/.nym/nym-nodes/default-nym-node/data/ed25519_bridge_identity.pem

# Derive and format the associated ed25519 public key Base64 encoded (used in the id_pubkey field in the client parameters)
openssl pkey -in private_key.pem -pubout | grep -v "\---" | base64 --decode | tail -c 32 | base64
```

#### 2) Bridge Configuration
The configuration for the nym-bridge runner includes the server side parameters for the running
bridge listener(s).  When launching the bridge runner the only argument needed is the path to this
configuration file. 

All of the transports are independent, so for example you could leave the tls_plain transport out of
the configuration file - or given that none of the ports collide, you could enable multiple
quic_plain listeners if there were a reason to do so.

This file needs saved to be provided to the nym-bridge binary (e.g.
`$HOME/.nym/nym-nodes/default-nym-node/config/bridges.toml`). 

The latest bridge config template for the configuration can be found in the root of the nym-bridge
directory.
<details>
<summary>Example Bridge Configuration template</summary>

```toml
# Nym Bridge Gateway Runner Configuration
#
# [version 0] - this is an initial implementation and the configuration handling will likely change
# going forward. This version is meant to be tightly coupled with a running `nym-node`.

# Path to file containing client parameters associated with the transports defined in this file
client_params_path = "/home/nym/.nym/nym-nodes/default-nym-node/config/client_bridge_params.json"

# Set of public IPs that address the listening host (usually and Ipv4 and IPv6 pair)
public_ips = ["192.168.0.1", "fe80::1"]

[forward]
# Target address where client traffic will be forwarded.
#
# If running in parallel with `nym-node` this should match with your public IP and announced wireguard port.
address = "[::1]:51822"

[[transports]]
transport_type = "quic_plain"

[transports.args]
# Enable stateless retries
stateless_retry = false

# Address to listen on
listen = "[::]:4443"

# Client address to block for sending, be default this is set by the OS on connection handling.
# block = "[2a01::1234]:5000" 

# Maximum number of concurrent connections to allow
# connection_limit = 0

# Path to file containing PKCS8 PEM encoded ed25519 identity private key, for use in ED25519 based self signed certs
private_ed25519_identity_key_file = '/etc/nym/default-nym-node/bridges/ed25519_identity'

# Base64 encoded Identity Key string. This is used to secure connections using ED25519 self signed
# certificates. Used only if `private_ed25519_identity_key_file` is not provided.
# identity_key = "<base64 encoded identity private key>"


[[transports]]
transport_type = "tls_plain"

[transports.args]
# Address to listen on
listen = "[::]:4443"

# Maximum number of concurrent connections to allow
# connection_limit = 0

# Path to file containing PKCS8 PEM encoded ed25519 identity private key, for use in ED25519 based self signed certs
private_ed25519_identity_key_file = '/etc/nym/default-nym-node/bridges/ed25519_identity'

# Base64 encoded Identity Key string. This is used to secure connections using ED25519 self signed
# certificates. Used only if `private_ed25519_identity_key_file` is not provided.
# identity_key = "<base64 encoded identity private key>"
```

</details>

Fields requiring manual review:

- `public_ips` - the globally routable addresses of the server.
  - `public_ips = ['1.1.1.1', 'fe80::1']`

- `forward.address` - The adress to which traffic will be sent after unwrapping the transport layer. This should be set to a PUBLIC IP of the nym node with the listening wireguard port.
  - `address = "1.1.1.1:51822"`

- `transports.args.identity_key` OR `transports.args.private_ed25519_identity_key_file` - Either a
  base64 encoded Ed25519 private key or the path the a PKCS8 PEM encoded ED25519 private key file.
  This is the key used to secure the transport connection. If a key was generated using openssl as
  described above, this is the place for the path to the private key.
  - `private_ed25519_identity_key_file = /home/nym/.nym/nym-nodes/default-nym-node/data/ed25519_bridge_identity.pem`

#### 3) Bridge client parameter file

Given the key material, IPs, ports, and any other parameters defined in the bridge configuration we
need to create a file that has all of the parameters that clients need to utilize the protocol. 

Once created this file needs saved (e.g.
`$HOME/.nym/nym-nodes/default-nym-node/config/client_bridge_params.json`). The path in the
nym-bridge configuration needs to point to this file. 

For the Quic (and TLS) transport the id_pubkey field is a base64 encoded ed25519 verifying (public) key.

<details>
<summary>Example Client Parameters File</summary>

```json
{
    "version": 0,
    "transports": [
        {
            "transport_type": "quic_plain",
            "args": {
                "addresses": ["[2a01:7e00::f03c:95ff:fef8:77f]:4443", "178.79.168.250:4443"],
                "id_pubkey": "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=",
                "host": "netdna.bootstrapcdn.com"
            }
        }
    ]
}
```

</details>


### Running Alongside a Nym Node

Add the path to the file containing the client bridge parameters to the nym-node configuration
(usually in `$HOME/.nym/nym-nodes/default-nym-node/config/config.toml`)

```diff
# ...
[gateway_tasks.storage_paths]
# Path to sqlite database containing all persistent data: messages for offline clients,
# derived shared keys, available client bandwidths and wireguard peers.
clients_storage = '/home/nym/.nym/nym-nodes/default-nym-node/data/clients.sqlite'

# Path to sqlite database containing all persistent stats data.
stats_storage = '/home/nym/.nym/nym-nodes/default-nym-node/data/stats.sqlite'

# Path to file containing cosmos account mnemonic used for zk-nym redemption.
cosmos_mnemonic = '/home/nym/.nym/nym-nodes/default-nym-node/data/cosmos_mnemonic'
+
+ # Path to file containing client params for nym bridges
+ bridge_client_params = '/home/nym/.nym/nym-nodes/default-nym-node/config/client_bridge_params.json'

##### service providers nym-node config options #####

[service_providers]
# ...
```

