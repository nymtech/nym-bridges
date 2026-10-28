# Upgrading nym-bridge to 0.3.0 (TLS and SSH transports)

This guide is for gateway operators who already run `nym-bridge` next to their `nym-node`.

## What is changing

`nym-bridge` has so far offered one transport, QUIC over UDP. In networks that block UDP or QUIC, NymVPN
users cannot reach it. Version 0.3.0 adds two TCP transports, TLS and SSH, which the app can fall back to
when QUIC is blocked. Your QUIC transport keeps working exactly as before.

## Is the upgrade safe?

- **QUIC is unchanged.** Same port, same protocol and the same identity key. The QUIC transport code is
  unchanged from 0.2.2 (only dependency versions were updated), and the upgrade script checks your published
  QUIC key afterwards and restores your backup if it would change.
- **Released apps keep working.** The `transports` list that existing apps read still contains QUIC only.
  TLS and SSH are published in a new `transports_v2` list, and apps that do not know it ignore it.
- **Do not enable TLS or SSH on 0.2.2.** Version 0.2.2 publishes them in the old `transports` list, which
  breaks apps up to 2026.12. Upgrade to 0.3.0 first. The script below does both in the right order.
- **Nothing is forced.** Run the script with `--no-tls-ssh` to upgrade the binaries and keep QUIC only.

## Before you start

- An amd64 Debian or Ubuntu host with glibc 2.34 or newer (Ubuntu 22.04+, Debian 12+), with `nym-node` and
  `nym-bridge` already set up (`/etc/nym/bridges.toml` exists). The script checks this and stops before
  changing anything if the host is older.
- Root access, and `curl`, `jq`, `ss`, `awk` and `dpkg` installed. Run the script inside `tmux` or `screen`
  so a dropped SSH session does not interrupt it (an interrupt also restores the backup).
- Know where your firewalls are. There are usually two:
  1. the **host** firewall (ufw, firewalld or iptables), which the script handles
  2. your **provider's** firewall (cloud security group, edge firewall, hosting panel), which you must
     change yourself

## Upgrade

```bash
curl -fsSLO https://raw.githubusercontent.com/nymtech/nym-bridges/main/scripts/upgrade-nym-bridge.sh
less upgrade-nym-bridge.sh        # read it before you run it
sudo bash upgrade-nym-bridge.sh v0.3.0
```

The script:

1. checks your current QUIC key and backs up `/etc/nym` to `/etc/nym.bak-<timestamp>`
2. installs the `.deb` for the release you name. If an older install left copies of `nym-bridge` or
   `bridge-cfg` in `/usr/local/bin`, they become links to the packaged binaries so your service keeps its path
3. adds the TLS (TCP 4443) and SSH (TCP 4422) transports to `bridges.toml`, creating keys only for those
   two and keeping your QUIC key. If another program already listens on one of those TCP ports, it skips that
   transport and warns you
4. opens the configured ports in ufw, firewalld or iptables
5. restarts `nym-bridge`, checks that it listens on every configured port and that the QUIC key is unchanged

If any step fails it restores your config and any binaries it moved, restarts the service, then prints the
reason. It does not downgrade the package.

## Open the ports at your provider

Allow **inbound** traffic (IPv4 and IPv6) to your node for:

| Protocol | Port | Purpose |
|---|---|---|
| UDP | 4443 | QUIC (already open on a working bridge) |
| TCP | 4443 | TLS |
| TCP | 4422 | SSH |

If you changed the listen ports in `bridges.toml`, open those instead. The script prints the exact list.

Check from **another machine** that the TCP ports answer:

```bash
nc -vz <your public IP> 4443
nc -vz <your public IP> 4422
```

A timeout means a firewall between you and the node is still blocking the port. "Connection refused" means
the port is open but nothing listens on it.

## Verify

```bash
systemctl status nym-bridge --no-pager
journalctl -u nym-bridge -n 30 --no-pager      # expect quic, tls and ssh "transport listening" lines
ss -lntup | grep -E ':4443|:4422'
curl -s http://127.0.0.1:8080/api/v1/bridges/client-params | jq '{transports: (.transports|length), transports_v2: (.transports_v2|length)}'
```

You should see `transports: 1` (QUIC only, for older apps) and `transports_v2: 3`. The QUIC `id_pubkey` must be
the same as before the upgrade.

## Using the Nym tunnel manager

If your host firewall is managed by `network-tunnel-manager.sh`, it may replace rules added by hand. Its TCP
allow list needs `4443` and `4422` as well. Check the version you run, and after any run of the tunnel manager
check the ports still answer from another machine (see above).

## If something goes wrong

- **The script says the QUIC key changed.** It has already restored your backup. Nothing was lost. Do not
  re-run it by hand with other options. Send the output to the Nym team.
- **TLS or SSH time out from outside.** Almost always the provider firewall. Re-check the table above.
- **Roll back manually:**
  ```bash
  sudo cp -a /etc/nym.bak-<timestamp>/. /etc/nym/
  sudo systemctl restart nym-bridge
  ```
- **Do not** run `bridge-cfg --gen` without `-i`, or use `--allow-overwrite`, on a live node. Either one can
  create a new QUIC key and break the users who rely on the old one.

## Questions

Ask in the operators channel and include the script output and `journalctl -u nym-bridge -n 50`.
