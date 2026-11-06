#!/bin/bash
# Commands in single quotes expand inside the containers.
# shellcheck disable=SC2016
# amneziawg-go v3.1 (the library the apps ship) through the QUIC bridge with AmneziaWG off: what the
# client does when bridges are on. Needs Docker; reuses the awg-lab.sh environment.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
wg0() { docker exec wg0 bash -c "$1"; }
wg1() { docker exec wg1 bash -c "$1"; }

docker compose up -d >/dev/null 2>&1
wg0 'cat /etc/amneziawg-go.versions'
wg1 'pgrep -x nym-bridge >/dev/null || (nym-bridge -c /etc/nym/default-nym-node/server.toml >/dev/null 2>&1 &); for _ in $(seq 100); do ss -lun | grep -q ":4433 " && exit 0; sleep 0.2; done; exit 1'
wg1 'pkill iperf3; sleep 0.5; iperf3 -s -D'
wg0 'wg-quick down wg-q0 >/dev/null 2>&1; wg-quick down wg0 >/dev/null 2>&1; ip link del awg0 2>/dev/null; pkill client-udp; true'
wg0 '(setsid client-udp --config /etc/nym/default-nym-node/client_quic.toml </dev/null >/tmp/quic.log 2>&1 &); sleep 1'
# Plain WireGuard UAPI (no jc/s/h keys) from amneziawg-go v3.1 to the local QUIC forwarder.
wg0 'hex() { echo "$1" | base64 -d | xxd -p -c 64; }
    rm -f /var/run/amneziawg/awg0.sock; amneziawg-go awg0 >/dev/null 2>&1
    for _ in $(seq 50); do [ -S /var/run/amneziawg/awg0.sock ] && break; sleep 0.1; done
    printf "%s\n" set=1 "private_key=$(hex UKaUwrThsQZ2fdO82REWHr2dQXMaot3BFb91f+ttE0Q=)" \
        "public_key=$(hex 9LVtZwHPXD0KMdYKRPmyiQhE+/hTcPuT8eCmLo5PsXw=)" endpoint=[::1]:8080 \
        persistent_keepalive_interval=5 allowed_ip=10.0.1.2/32 "" | socat - UNIX-CONNECT:/var/run/amneziawg/awg0.sock >/dev/null
    ip address add 10.0.1.1/24 dev awg0; ip link set awg0 mtu 1420 up'

if wg0 'for _ in $(seq 30); do ping -c 1 -W 1 10.0.1.2 >/dev/null && exit 0; done; exit 1'; then
    pass "amneziawg-go v3.1 (AmneziaWG off) connects through the QUIC bridge"
else
    fail "amneziawg-go v3.1 (AmneziaWG off) connects through the QUIC bridge"
fi
down=$(wg0 "iperf3 -c 10.0.1.2 -t 8 -R -f m 2>/dev/null | awk '/receiver/ {print \$7}'")
if [ -n "$down" ]; then pass "traffic flows through the QUIC bridge ($down Mbit/s down)"; else fail "traffic flows through the QUIC bridge"; fi

wg0 'ip link del awg0; pkill client-udp; true'
exit "$FAILED"
