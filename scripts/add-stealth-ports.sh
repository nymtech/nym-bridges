#!/usr/bin/env bash
# Add the TLS (443) and SSH (2222) transports alongside whatever a node already has, without
# touching or restarting anything until the very last step.
#
# `upgrade-nym-bridge.sh` only adds a transport the first time its type appears at all, so a node
# that already had tls_plain/ssh_plain configured at other ports before 0.3.0 never gets the new
# default ports from it. This script adds a second listener of each type, at the target port,
# alongside the existing one - safe to run on a node that's been serving real traffic the whole
# time, and safe to re-run (each transport is skipped once it's already at the target port).
#
# usage: sudo ./add-stealth-ports.sh [--tls-port=PORT] [--ssh-port=PORT]
#   --tls-port   TCP port to add for TLS (default: 443)
#   --ssh-port   TCP port to add for SSH (default: 2222)
#
# If the target TLS port is already bound by something else (commonly nginx, terminating this
# node's own HTTPS), this script does NOT touch it or try to rewrite that config - every
# operator's setup differs too much to do that safely. It skips that transport and prints the
# nginx stream/ssl_preread recipe to share the port instead; see docs/SHARING-PORT-443.md.
set -Eeuo pipefail

CONF=/etc/nym/bridges.toml
NODE_CFG="${NODE_CFG:-$(find "${HOME:-/root}/.nym/nym-nodes" -name config.toml 2>/dev/null | head -n1 || true)}"
KEYS_DIR=/etc/nym/keys
BAK="/etc/nym.bak-stealth-$(date +%F-%H%M%S)"

TLS_PORT=443
SSH_PORT=2222
for arg in "$@"; do
  case "$arg" in
    --tls-port=*) TLS_PORT="${arg#*=}" ;;
    --ssh-port=*) SSH_PORT="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done
for p in "$TLS_PORT" "$SSH_PORT"; do
  [[ "$p" =~ ^[0-9]+$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 )) || { echo "invalid port: $p" >&2; exit 1; }
done
[[ "$TLS_PORT" != "$SSH_PORT" ]] || { echo "--tls-port and --ssh-port must differ (both $TLS_PORT)" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for c in openssl jq dpkg systemctl ss awk bridge-cfg; do
  command -v "$c" >/dev/null || { echo "missing: $c (this script supports Debian and Ubuntu)" >&2; exit 1; }
done
[[ -f "$CONF" ]] || { echo "expected $CONF; run the full bridge setup first" >&2; exit 1; }
[[ -f "$NODE_CFG" ]] || { echo "set NODE_CFG to your nym-node config.toml" >&2; exit 1; }

# prints "<transport_type> <port>" for every transport already in CONF
list_ports() {
  awk -F"[\"']" '/^\[\[transports\]\]/ {t=""} /^[[:space:]]*transport_type[[:space:]]*=/ {t=$2} /^[[:space:]]*listen[[:space:]]*=/ && t != "" {n=split($2,a,":"); print t, a[n]}' "$1"
}

already_at_port() { # transport_type port
  list_ports "$CONF" | grep -qx "$1 $2"
}

port_free() { # port proto(tcp|udp)
  ! ss -ln"${2:0:1}"p "sport = :$1" 2>/dev/null | grep -q LISTEN
}

quic_key() { jq -r '.transports[]?|select(.transport_type=="quic_plain").args.id_pubkey' /etc/nym/client_bridge_params.json 2>/dev/null || true; }
BEFORE_QUIC="$(quic_key)"

# Plan first, with no side effects, so a node that's already fully configured (the common case on
# a re-run) never touches disk or restarts anything.
TO_ADD=()

if already_at_port ssh_plain "$SSH_PORT"; then
  echo "ssh_plain already configured on $SSH_PORT, nothing to do for SSH"
elif port_free "$SSH_PORT" tcp; then
  TO_ADD+=("ssh_plain $SSH_PORT")
else
  echo "WARNING: TCP $SSH_PORT is already in use, not adding ssh_plain there" >&2
fi

if already_at_port tls_plain "$TLS_PORT"; then
  echo "tls_plain already configured on $TLS_PORT, nothing to do for TLS"
elif port_free "$TLS_PORT" tcp; then
  TO_ADD+=("tls_plain $TLS_PORT")
else
  holder="$(ss -ltnp "sport = :$TLS_PORT" 2>/dev/null | awk 'NR==2{print $NF}')"
  cat >&2 <<EOF

TCP $TLS_PORT is already in use by: ${holder:-an unknown process}
Not adding tls_plain there automatically - every operator's setup on that port differs too much
to rewrite safely from a script. If that's nginx (or another reverse proxy) terminating this
node's own HTTPS, you can share port $TLS_PORT between it and nym-bridge: the proxy inspects the
TLS ClientHello's SNI without decrypting it, and forwards non-matching connections straight
through to nym-bridge on a loopback-only port. See docs/SHARING-PORT-443.md for the exact nginx
recipe (stream + ssl_preread), written from doing exactly this on a real node.
EOF
fi

if [[ "${#TO_ADD[@]}" -eq 0 ]]; then
  echo "nothing to do"
  exit 0
fi

cp -a /etc/nym "$BAK"
rollback() {
  echo "FAILED: restoring $BAK and restarting nym-bridge" >&2
  cp -a "$BAK"/. /etc/nym/ || true
  systemctl restart nym-bridge || true
}
trap rollback ERR

# Appends a second `[[transports]]` entry for an already-present transport type, at a new port,
# with its own freshly generated key - never touches the existing entry or its key.
for entry in "${TO_ADD[@]}"; do
  ttype="${entry% *}"; port="${entry#* }"
  key="$KEYS_DIR/${ttype%_plain}_${port}_ed25519_identity.pem"
  [[ -f "$key" ]] || openssl genpkey -algorithm ed25519 -out "$key" >/dev/null 2>&1
  chmod 640 "$key"
  chown root:nym "$key" 2>/dev/null || true
  {
    echo
    echo "[[transports]]"
    echo "transport_type = \"$ttype\""
    echo
    echo "[transports.args]"
    echo "listen = \"[::]:$port\""
    echo "private_ed25519_identity_key_file = \"$key\""
  } >> "$CONF"
  echo "added $ttype on $port"
done

bridge-cfg --gen -i "$CONF" -n "$NODE_CFG" -d /etc/nym -o "$CONF"

systemctl restart nym-bridge
missing=""
for _ in $(seq 15); do
  sleep 2
  missing=""
  systemctl is-active --quiet nym-bridge || missing="nym-bridge is not active"
  while read -r t port; do
    [[ -n "$port" ]] || continue
    flag=t; [[ "$t" == quic_plain ]] && flag=u
    ss -ln"$flag"p 2>/dev/null | grep -q ":$port " || missing="not listening on $t port $port"
  done <<< "$(list_ports "$CONF")"
  [[ -z "$missing" ]] && break
done
[[ -z "$missing" ]] || { echo "$missing" >&2; false; }
[[ "$(quic_key)" == "$BEFORE_QUIC" ]] || { echo "QUIC key changed after restart" >&2; false; }

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
for entry in "${TO_ADD[@]}"; do
  open_port tcp "${entry#* }"
done
[[ "$FIREWALLD_RELOAD" -eq 1 ]] && firewall-cmd --reload >/dev/null
command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null || true

trap - ERR
echo
echo "OK. Backup kept at $BAK"
echo "Added: ${TO_ADD[*]}"
echo "Remaining step: allow these in your cloud provider's firewall / security group too (IPv4 and IPv6)."
echo "Then, from ANOTHER machine, check the TCP ports answer:  nc -vz <your public IP> <port>"
