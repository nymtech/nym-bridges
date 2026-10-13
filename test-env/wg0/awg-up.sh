#!/bin/bash
# awg-up <amneziawg-go binary> <base|awg10|awg31>: bring up awg0 against wg1.
#   base  - AmneziaWG base mode (junk packets only) to the plain WireGuard port, as on gateways
#           without a translator
#   awg10 - AmneziaWG 1.0 through the translator on :51830
#   awg31 - AmneziaWG 3.1 through the translator on :51831 (MTU lowered by S4 = 16)
# Params match test-config/server.toml; key order matches what nym-vpn-client sends
# (nym-vpn-lib test `amnezia_entry_matches_lab_verified_uapi`).
set -euo pipefail

bin=$1
profile=$2
hex() { echo "$1" | base64 -d | xxd -p -c 64; }

case "$profile" in
    base)
        endpoint=192.168.100.3:51821 address=10.0.0.1/24 peer_ip=10.0.0.2/32 mtu=1420
        extra=() ;;
    awg10)
        endpoint=192.168.100.3:51830 address=10.0.1.1/24 peer_ip=10.0.1.2/32 mtu=1420
        extra=("s1=44" "s2=52" "h1=1" "h2=2" "h3=123456789" "h4=1623456789") ;;
    awg31)
        endpoint=192.168.100.3:51831 address=10.0.1.1/24 peer_ip=10.0.1.2/32 mtu=1404
        extra=("s1=44" "s2=52" "h1=1" "h2=2" "h3=123456789-123456889" "h4=1623456789-1623456889"
            "s3=20" "s4=16"
            "header_protection_key=0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"
            "random_trailers=true") ;;
    *) echo "unknown profile '$profile'" >&2; exit 2 ;;
esac

ip link del awg0 2>/dev/null || true
rm -f /var/run/amneziawg/awg0.sock
"$bin" awg0
for _ in $(seq 50); do
    [ -S /var/run/amneziawg/awg0.sock ] && break
    sleep 0.1
done

reply=$(printf '%s\n' \
    "set=1" \
    "private_key=$(hex UKaUwrThsQZ2fdO82REWHr2dQXMaot3BFb91f+ttE0Q=)" \
    "jc=4" "jmin=40" "jmax=70" \
    "${extra[@]}" \
    "public_key=$(hex 9LVtZwHPXD0KMdYKRPmyiQhE+/hTcPuT8eCmLo5PsXw=)" \
    "endpoint=$endpoint" \
    "persistent_keepalive_interval=5" \
    "allowed_ip=$peer_ip" \
    "" | socat - UNIX-CONNECT:/var/run/amneziawg/awg0.sock)
[ "$reply" = "errno=0" ] || { echo "awg0 config rejected: $reply" >&2; exit 1; }

ip address add "$address" dev awg0
ip link set awg0 mtu "$mtu" up
