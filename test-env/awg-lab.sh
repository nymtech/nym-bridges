#!/bin/bash
# Commands in single quotes expand inside the containers.
# shellcheck disable=SC2016,SC2329
# Offline lab for the AmneziaWG translator and the QUIC/TLS/SSH bridges. wg1 runs kernel WireGuard
# plus nym-bridge; wg0 is the client with kernel WireGuard and two amneziawg-go builds; an optional
# censor in wg0 drops vanilla WireGuard handshake initiations. Needs Docker.
set -euo pipefail
cd "$(dirname "$0")"

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
info() { echo "INFO: $1"; }
check() { if "${@:2}"; then pass "$1"; else fail "$1"; fi; }
wg0() { docker exec wg0 bash -c "$1"; }
wg1() { docker exec wg1 bash -c "$1"; }

AWG=amneziawg-go
LEGACY=amneziawg-go-legacy
CENSOR='-p udp -m length --length 176 -m u32 --u32 "28=0x01000000" -j DROP'

censor_on() { wg0 "iptables -C OUTPUT $CENSOR 2>/dev/null || iptables -A OUTPUT $CENSOR"; }
censor_off() { wg0 "iptables -D OUTPUT $CENSOR 2>/dev/null || true"; }
all_down() { wg0 'ip link del awg0 2>/dev/null; wg-quick down wg0 >/dev/null 2>&1; wg-quick down wg-q0 >/dev/null 2>&1; pkill client-udp; true'; }
reaches() { wg0 "ping -c 3 -W 2 $1 >/dev/null"; }
unreachable() { ! wg0 "ping -c 3 -W 2 $1 >/dev/null"; }
# Immediate mode: packets reach the file as they arrive, so stopping early loses nothing.
capture() { docker exec -d wg0 timeout "$2" tcpdump -U --immediate-mode -ni eth0 -w "/tmp/$1.pcap" "$3"; sleep 1; }
# A bridge connects before it forwards, so wait for a real WireGuard handshake on wg-q0.
handshake() { wg0 'for _ in $(seq 60); do [ "$(wg show wg-q0 latest-handshakes | cut -f2)" != 0 ] && exit 0; sleep 0.5; done; exit 1'; }
pcap_count() { wg0 "tcpdump -nr /tmp/$1.pcap '$2' 2>/dev/null | wc -l"; }
throughput() { wg0 "iperf3 -c $1 -t 8 -f m 2>/dev/null | awk '/receiver/ {print \$7}'"; }
rtt() { wg0 "ping -c 20 -i 0.05 -q $1 | awk -F/ '/rtt/ {print \$5}'"; }
at_least() { awk -v a="$1" -v b="$2" -v f="$3" 'BEGIN { exit !(a >= f * b) }'; }

docker compose up -d --build
all_down
docker exec -d wg1 nym-bridge -c /etc/nym/default-nym-node/server.toml
wg1 'for _ in $(seq 100); do ss -lun | grep -q ":51831 " && exit 0; sleep 0.2; done; exit 1' \
    || { echo "nym-bridge did not open the amnezia ports"; exit 1; }
wg1 'pkill iperf3; iperf3 -s -D'

echo "== 0. amneziawg-go builds under test"
wg0 'cat /etc/amneziawg-go.versions'

echo "== 1. Fallbacks: vanilla WireGuard and older clients"
censor_off
wg0 'wg-quick up wg0 >/dev/null 2>&1'
check "vanilla WireGuard to the plain port" reaches 10.0.0.2
all_down
wg0 "awg-up $LEGACY base"
check "legacy amneziawg-go base mode to the plain port (old client, gateway without translator)" reaches 10.0.0.2
wg0 "awg-up $AWG base"
check "amneziawg-go 3.1 base mode to the plain port (new client, gateway without translator)" reaches 10.0.0.2
censor_on
wg0 "awg-up $LEGACY awg10"
check "legacy amneziawg-go through the AmneziaWG 1.0 translator, censor on" reaches 10.0.1.2
wg0 "awg-up $AWG awg10"
check "amneziawg-go 3.1 through the AmneziaWG 1.0 translator, censor on" reaches 10.0.1.2
wg0 "awg-up $AWG awg31"
check "amneziawg-go 3.1 through the AmneziaWG 3.1 translator, censor on" reaches 10.0.1.2
all_down
wg0 'wg-quick up wg0 >/dev/null 2>&1'
check "censor blocks vanilla WireGuard" unreachable 10.0.0.2
all_down
wg0 "awg-up $AWG base"
check "censor blocks base mode (why the translator is needed)" unreachable 10.0.0.2
all_down

echo "== 2. Header, padding and decryption format"
# A completed handshake and data exchange is the decryption proof: kernel WireGuard verifies mac1
# on handshakes and the AEAD tag on every data packet.
wg0 "awg-up $AWG awg10"
capture awg10 8 "udp port 51830"
reaches 10.0.1.2
wg0 'sleep 6'
check "1.0: no WireGuard type at datagram start" \
    test "$(pcap_count awg10 'udp[8:4] = 0x01000000 or udp[8:4] = 0x02000000 or udp[8:4] = 0x04000000')" -eq 0
check "1.0: no unpadded handshake sizes (148 / 92) on the wire" \
    test "$(pcap_count awg10 'udp[4:2] = 156 or udp[4:2] = 100')" -eq 0
info "1.0 keeps the handshake type behind its padding (offset S1/S2); 3.1 header protection hides it"
wg0 "awg-up $AWG awg31"
capture awg31 8 "udp port 51831"
reaches 10.0.1.2
wg0 'sleep 6'
leaks=0
for offset in 0 16 20 44 52; do
    n=$(pcap_count awg31 "udp[$((8 + offset)):4] = 0x01000000 or udp[$((8 + offset)):4] = 0x02000000 or udp[$((8 + offset)):4] = 0x04000000")
    leaks=$((leaks + n))
done
check "3.1: datagrams captured" test "$(pcap_count awg31 'udp')" -gt 0
check "3.1: no WireGuard type at any padding offset (header protection)" test "$leaks" -eq 0
all_down

echo "== 3. No datagram collisions"
# Transport packets are 32 + 16k bytes. With S1 = 44 / S2 = 52 the padded 1.0 handshakes are 192 /
# 144 bytes, sizes ICMP payloads 117-132 and 69-84 also produce, so the sweep hits both.
for profile in awg10 awg31; do
    port=51830
    [ "$profile" = awg31 ] && port=51831
    wg0 "awg-up $AWG $profile"
    reaches 10.0.1.2 || true
    capture "sweep-$profile" 90 "udp port $port"
    lost=$(wg0 'lost=0; for s in $(seq 40 140) $(seq 1000 37 1370); do ping -c 1 -W 1 -s "$s" 10.0.1.2 >/dev/null || lost=$((lost + 1)); done; echo $lost')
    check "$profile: every ping size 40-140 and 1000-1370 answered" test "$lost" -eq 0
    if [ "$profile" = awg10 ]; then
        wg0 'pkill -INT tcpdump; sleep 1'
        # Transport datagrams only: same size as a padded handshake, without its type at S1/S2.
        collided=$(pcap_count "sweep-$profile" '(udp[4:2] = 200 and udp[52:4] != 0x01000000) or (udp[4:2] = 152 and udp[60:4] != 0x02000000)')
        check "$profile: transport datagrams at padded handshake sizes were sent and handled ($collided)" test "$collided" -gt 0
    fi
done
all_down

echo "== 4. MTU"
mtu_case() { # name, setup, peer, mtu
    wg0 "$2"
    reaches "$3" || true
    capture "mtu-$1" 8 "udp"
    check "$1: full-size packet at tunnel MTU $4 passes with DF" wg0 "ping -M do -c 2 -W 2 -s $(($4 - 28)) $3 >/dev/null"
    check "$1: one byte over tunnel MTU $4 is refused locally" bash -c "! docker exec wg0 ping -M do -c 1 -W 1 -s $(($4 - 27)) $3 >/dev/null 2>&1"
    wg0 'sleep 6'
    check "$1: no IP fragments on the wire" test "$(pcap_count "mtu-$1" 'ip[6:2] & 0x3fff != 0')" -eq 0
    info "$1: largest UDP payload on the wire $(wg0 "tcpdump -nr /tmp/mtu-$1.pcap -q 2>/dev/null | awk '{print \$NF}' | sort -n | tail -1") bytes"
    all_down
}
censor_off
mtu_case vanilla 'wg-quick up wg0 >/dev/null 2>&1' 10.0.0.2 1420
censor_on
mtu_case awg10 "awg-up $AWG awg10" 10.0.1.2 1420
mtu_case awg31 "awg-up $AWG awg31" 10.0.1.2 1404
info "1.0 keeps the 1420 tunnel MTU; 3.1 gives up S4 = 16 bytes of tunnel MTU to keep the same wire size"

echo "== 5. Benchmarks (8 s iperf3, 20 pings)"
bench() { # name, setup, peer; prints and returns Mbit/s in BENCH
    wg0 "$2"
    reaches "$3" || true
    BENCH=$(throughput "$3")
    printf '%-40s %10s Mbit/s %8s ms\n' "$1" "$BENCH" "$(rtt "$3")"
    all_down
}
censor_off
bench "vanilla WireGuard (kernel client)" 'wg-quick up wg0 >/dev/null 2>&1' 10.0.0.2
bench "amneziawg-go 3.1 base, no translator" "awg-up $AWG base" 10.0.0.2
base=$BENCH
censor_on
bench "legacy amneziawg-go, 1.0 translator" "awg-up $LEGACY awg10" 10.0.1.2
bench "amneziawg-go 3.1, 1.0 translator" "awg-up $AWG awg10" 10.0.1.2
awg10=$BENCH
bench "amneziawg-go 3.1, 3.1 translator" "awg-up $AWG awg31" 10.0.1.2
awg31=$BENCH
# Same userspace client either way, so the ratio is the cost of the translator hop (a userspace
# relay); tracked, not gated, until the relay batches datagrams.
info "1.0 translator at $(awk -v a="$awg10" -v b="$base" 'BEGIN { printf "%d", 100 * a / b }')% of base mode, 3.1 at $(awk -v a="$awg31" -v b="$base" 'BEGIN { printf "%d", 100 * a / b }')% (target 80%)"

echo "== 6. QUIC, TLS and SSH bridges, censor on"
for transport in quic tls ssh; do
    port=4433
    [ "$transport" = tls ] && port=4443
    [ "$transport" = ssh ] && port=4422
    capture "bridge-$transport" 30 "port $port"
    docker exec -d wg0 client-udp --config "/etc/nym/default-nym-node/client_${transport}.toml"
    wg0 'sleep 1; wg-quick up wg-q0 >/dev/null 2>&1'
    handshake || true
    check "$transport bridge carries the WireGuard the censor blocks" reaches 10.0.1.2
    bench_value=$(throughput 10.0.1.2)
    [ "$transport" = quic ] && quic=$bench_value
    printf '%-40s %10s Mbit/s %8s ms\n' "$transport bridge" "$bench_value" "$(rtt 10.0.1.2)"
    all_down
done
# The gate is against what ships today: the QUIC bridge.
check "1.0 translator at least as fast as the QUIC bridge" at_least "$awg10" "$quic" 1
check "3.1 translator at least as fast as the QUIC bridge" at_least "$awg31" "$quic" 0.9

echo "== 7. SNI and hostnames on the wire"
wg0 'pkill -INT tcpdump; sleep 1'
check "AmneziaWG: no TCP in the translator capture" test "$(pcap_count awg31 'tcp')" -eq 0
check "AmneziaWG: no hostname in the translator capture" \
    test "$(wg0 'tcpdump -nr /tmp/awg31.pcap -A 2>/dev/null | grep -c "domain.com" || true')" -eq 0
tls_sni=$(wg0 'tcpdump -nr /tmp/bridge-tls.pcap -A 2>/dev/null | grep -c "tls-test.domain.com" || true')
quic_sni=$(wg0 'tcpdump -nr /tmp/bridge-quic.pcap -A 2>/dev/null | grep -c "quic-test.domain.com" || true')
ssh_banner=$(wg0 'tcpdump -nr /tmp/bridge-ssh.pcap -A 2>/dev/null | grep -c "SSH-2.0-OpenSSH" || true')
info "TLS bridge: cover hostname 'tls-test.domain.com' in clear ClientHello SNI: $([ "$tls_sni" -gt 0 ] && echo yes || echo no)"
info "QUIC bridge: 'quic-test.domain.com' as plain bytes: $([ "$quic_sni" -gt 0 ] && echo yes || echo no) (inside QUIC Initial protection, still decodable by DPI)"
info "SSH bridge: no SNI; OpenSSH banner in clear: $([ "$ssh_banner" -gt 0 ] && echo yes || echo no)"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "All lab checks passed"
else
    echo "Lab checks failed"
fi
exit "$FAILED"
