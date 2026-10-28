#!/usr/bin/env bash
# Upgrade nym-bridge on an existing node to a GitHub release and add the TLS and SSH transports.
#
# - backs up /etc/nym first and restores it (and restarts the service) if any step fails
# - never regenerates the QUIC identity key; it stops if the published QUIC key changes
# - opens the configured listen ports in ufw, firewalld or iptables, whichever the host uses
#
# usage: sudo ./upgrade-nym-bridge.sh [TAG] [--no-tls-ssh]
#   TAG            release tag to install (default: v0.3.0). Pre-releases work, e.g. v0.3.0-rc.1
#   --no-tls-ssh   upgrade the binaries only and leave the transports in bridges.toml as they are
#
# Your cloud provider's firewall (security group) is separate from the host firewall and is not
# changed by this script: allow the TCP ports it prints at the end there as well.
set -Eeuo pipefail

# prints "<transport_type> <port>" for every transport in a bridges.toml
list_ports() {
  awk -F"[\"']" '/^\[\[transports\]\]/ {t=""} /^[[:space:]]*transport_type[[:space:]]*=/ {t=$2} /^[[:space:]]*listen[[:space:]]*=/ && t != "" {n=split($2,a,":"); print t, a[n]}' "$1"
}

TAG="v0.3.0"
ADD_TLS_SSH=1
for arg in "$@"; do
  case "$arg" in
    --no-tls-ssh) ADD_TLS_SSH=0 ;;
    v*) TAG="$arg" ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

CONF=/etc/nym/bridges.toml
NODE_CFG="${NODE_CFG:-$(find "${HOME:-/root}/.nym/nym-nodes" -name config.toml 2>/dev/null | head -n1 || true)}"
BAK="/etc/nym.bak-$(date +%F-%H%M%S)"

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for c in curl jq dpkg systemctl ss awk; do
  command -v "$c" >/dev/null || { echo "missing: $c (this script supports Debian and Ubuntu)" >&2; exit 1; }
done
[[ -f "$CONF" ]] || { echo "expected $CONF; run the full bridge setup first" >&2; exit 1; }
[[ -f "$NODE_CFG" ]] || { echo "set NODE_CFG to your nym-node config.toml" >&2; exit 1; }
[[ "$(dpkg --print-architecture)" == amd64 ]] || { echo "the release .deb is amd64 only" >&2; exit 1; }
libc="$(dpkg-query -W -f='${Version}' libc6 2>/dev/null || true)"
dpkg --compare-versions "${libc:-0}" ge 2.34 ||
  { echo "needs glibc 2.34 or newer (Ubuntu 22.04+, Debian 12+); found ${libc:-none}" >&2; exit 1; }

PARAMS="$(awk -F'"' '/^client_params_path/ {print $2}' "$CONF")"
PARAMS="${PARAMS:-/etc/nym/client_bridge_params.json}"
[[ -f "$PARAMS" ]] || { echo "expected $PARAMS" >&2; exit 1; }

quic_key() { jq -r '.transports[]|select(.transport_type=="quic_plain").args.id_pubkey' "$PARAMS"; }
before="$(quic_key)"
[[ -n "$before" && "$before" != null ]] || { echo "cannot read the current QUIC key from $PARAMS" >&2; exit 1; }
echo "QUIC key before: $before"

cp -a /etc/nym "$BAK"
rollback() {
  echo "FAILED: restoring $BAK and restarting nym-bridge" >&2
  cp -a "$BAK"/. /etc/nym/ || true
  for b in nym-bridge bridge-cfg; do
    if [[ -e "/usr/local/bin/$b.old" ]]; then mv -f "/usr/local/bin/$b.old" "/usr/local/bin/$b" || true; fi
  done
  systemctl restart nym-bridge || true
}
trap rollback ERR
trap 'rollback; exit 1' INT TERM HUP
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

url="$(curl -fsSL "https://api.github.com/repos/nymtech/nym-bridges/releases/tags/$TAG" \
  | jq -r '.assets[]|select(.name|endswith(".deb"))|.browser_download_url')"
[[ -n "$url" ]] || { echo "no .deb asset on release $TAG" >&2; false; }
curl -fL -o "$TMP/nym-bridge.deb" "$url"

# an older install may run the service from /usr/local/bin: keep that path valid, on the new binary
for b in nym-bridge bridge-cfg; do
  if [[ -e "/usr/local/bin/$b" && ! -L "/usr/local/bin/$b" ]]; then mv "/usr/local/bin/$b" "/usr/local/bin/$b.old"; fi
done
dpkg -i "$TMP/nym-bridge.deb"
for b in nym-bridge bridge-cfg; do
  if [[ -e "/usr/local/bin/$b.old" ]]; then ln -sf "/usr/bin/$b" "/usr/local/bin/$b"; fi
done

if [[ "$ADD_TLS_SSH" -eq 1 ]]; then
  for t in tls_plain:4443 ssh_plain:4422; do
    name="${t%%:*}"; port="${t##*:}"
    if ! grep -Eq "^[[:space:]]*transport_type[[:space:]]*=[[:space:]]*\"$name\"" "$CONF"; then
      listening="$(ss -ltn "sport = :$port")"
      if grep -q LISTEN <<< "$listening"; then
        echo "WARNING: TCP $port is already in use on this host, not adding $name" >&2
        continue
      fi
      printf '\n[[transports]]\ntransport_type = "%s"\n[transports.args]\nlisten = "[::]:%s"\n' "$name" "$port" >> "$CONF"
    fi
  done
  # -i keeps the existing QUIC key; only transports without a key get a new one
  bridge-cfg --gen -i "$CONF" -n "$NODE_CFG" -d /etc/nym -o "$CONF"
fi

after="$(quic_key)"
[[ "$before" == "$after" ]] || { echo "QUIC key changed ($after)" >&2; false; }

FIREWALLD_RELOAD=0
open_port() {
  local proto="$1" port="$2"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$port/$proto" >/dev/null
    echo "ufw: allowed $port/$proto"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/$proto" >/dev/null
    FIREWALLD_RELOAD=1
    echo "firewalld: allowed $port/$proto"
  else
    local ipt
    for ipt in iptables ip6tables; do
      command -v "$ipt" >/dev/null || continue
      "$ipt" -C INPUT -p "$proto" --dport "$port" -m comment --comment NYM-BRIDGE -j ACCEPT 2>/dev/null ||
        "$ipt" -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment NYM-BRIDGE -j ACCEPT
    done
    echo "iptables: allowed $port/$proto"
  fi
}

# quic is UDP, tls and ssh are TCP
PORTS="$(list_ports "$CONF")"
while read -r t port; do
  [[ -n "$port" ]] || continue
  proto=tcp; [[ "$t" == quic_plain ]] && proto=udp
  open_port "$proto" "$port"
done <<< "$PORTS"
[[ "$FIREWALLD_RELOAD" -eq 1 ]] && firewall-cmd --reload >/dev/null
command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null || true

systemctl restart nym-bridge
# a slow host can take a while to load the keys, so wait up to 30 seconds for every listener
for _ in $(seq 15); do
  sleep 2
  missing=""
  systemctl is-active --quiet nym-bridge || missing="nym-bridge is not active"
  while read -r t port; do
    [[ -n "$port" ]] || continue
    flag=t; [[ "$t" == quic_plain ]] && flag=u
    listening="$(ss -ln"$flag"p 2>/dev/null || true)"
    grep -q ":$port " <<< "$listening" || missing="not listening on $t port $port"
  done <<< "$PORTS"
  [[ -z "$missing" ]] && break
done
[[ -z "$missing" ]] || { echo "$missing" >&2; false; }
[[ "$(quic_key)" == "$before" ]] || { echo "QUIC key differs after restart" >&2; false; }

trap - ERR INT TERM HUP
# the previous binaries were only needed for the rollback
rm -f /usr/local/bin/nym-bridge.old /usr/local/bin/bridge-cfg.old
echo
echo "OK. Backup kept at $BAK"
echo "Published transports:"
jq -r '.transports_v2[]? | "  \(.transport_type)  \(.args.addresses[0])"' "$PARAMS"
echo
echo "Remaining step: allow these in your cloud provider's firewall / security group (IPv4 and IPv6):"
while read -r t port; do
  [[ -n "$port" ]] || continue
  proto=TCP; [[ "$t" == quic_plain ]] && proto=UDP
  echo "  $proto $port  ($t)"
done <<< "$PORTS"
echo "Then, from ANOTHER machine, check the TCP ports answer:  nc -vz <your public IP> <port>"
