#!/bin/bash
# Commands in single quotes expand inside the containers.
# shellcheck disable=SC2016,SC2329
# Mobile and poor network profiles for the AmneziaWG translator and the QUIC/TLS/SSH bridges.
# tc netem shapes the link: wg1 egress is the download, wg0 egress the upload, and each side adds
# its one-way delay, jitter and loss. Needs Docker; reuses the awg-lab.sh environment.
set -euo pipefail
cd "$(dirname "$0")"

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
check() { if "${@:2}"; then pass "$1"; else fail "$1"; fi; }
wg0() { docker exec wg0 bash -c "$1"; }
wg1() { docker exec wg1 bash -c "$1"; }

CENSOR='-p udp -m length --length 176 -m u32 --u32 "28=0x01000000" -j DROP'
censor_on() { wg0 "iptables -C OUTPUT $CENSOR 2>/dev/null || iptables -A OUTPUT $CENSOR"; }
censor_off() { wg0 "iptables -D OUTPUT $CENSOR 2>/dev/null || true"; }
all_down() { wg0 'ip link del awg0 2>/dev/null; wg-quick down wg0 >/dev/null 2>&1; wg-quick down wg-q0 >/dev/null 2>&1; pkill client-udp; true'; }

# download upload one-way-delay jitter loss
profile() {
    case "$1" in
        3g) echo "3mbit 1mbit 100ms 25ms 1%" ;;
        4g) echo "30mbit 10mbit 30ms 8ms 0.3%" ;;
        5g) echo "200mbit 50mbit 10ms 3ms 0.05%" ;;
        poor) echo "512kbit 256kbit 300ms 100ms 5%" ;;
    esac
}
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

shape() {
    read -r down up delay jitter loss <<<"$(profile "$1")"
    wg1 "tc qdisc replace dev eth0 root netem rate $down delay $delay $jitter loss $loss limit 10000"
    wg0 "tc qdisc replace dev eth0 root netem rate $up delay $delay $jitter loss $loss limit 10000"
}
unshape() { wg0 'tc qdisc del dev eth0 root 2>/dev/null || true'; wg1 'tc qdisc del dev eth0 root 2>/dev/null || true'; }

# Seconds from bringing the path up until the first ping answers (60 s cap).
connect_time() { # setup, peer
    local start
    start=$(date +%s.%N)
    wg0 "$1" >/dev/null 2>&1
    wg0 "for _ in \$(seq 120); do ping -c 1 -W 1 $2 >/dev/null && exit 0; done; exit 1" || { echo fail; return; }
    awk -v s="$start" -v e="$(date +%s.%N)" 'BEGIN { printf "%.1f", e - s }'
}
mbit() { wg0 "iperf3 -c $1 -t 8 -f m $2 2>/dev/null | awk '/receiver/ {print \$7}'"; }
rtt() { wg0 "ping -c 10 -i 0.2 -q $1 | awk -F/ '/rtt/ {print \$5}'"; }

median() { printf '%s\n' "$@" | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

# Random loss makes single runs noisy, so connect time, download and upload are medians of $5 runs.
run_path() { # profile, name, setup, peer, runs
    local t down up r ts=() downs=() ups=()
    for _ in $(seq "$5"); do
        t=$(connect_time "$3" "$4")
        if [ "$t" = fail ]; then
            fail "$1 $2: connects within 60 s"
            all_down
            return
        fi
        ts+=("$t")
        downs+=("$(mbit "$4" -R)")
        ups+=("$(mbit "$4" "")")
        r=$(rtt "$4")
        all_down
    done
    t=$(median "${ts[@]}") down=$(median "${downs[@]:-0}") up=$(median "${ups[@]:-0}")
    echo "$1|$2|${down:-0}|${up:-0}" >>"$RESULTS"
    printf '%-6s %-22s %7s s %9s %9s %9s ms\n' "$1" "$2" "$t" "${down:-0}" "${up:-0}" "${r:-n/a}"
}
bridge_setup() { echo "pkill client-udp; setsid client-udp --config /etc/nym/default-nym-node/client_$1.toml </dev/null >/dev/null 2>&1 & sleep 1; wg-quick up wg-q0"; }

docker compose up -d --build
# Gateways get this from the package's sysctl file; the containers share the Docker VM's kernel.
docker run --rm --privileged --net=host --entrypoint sysctl test-env-wg1 -q -w net.core.rmem_max=4194304
all_down
unshape
wg1 'pgrep -x nym-bridge >/dev/null || (nym-bridge -c /etc/nym/default-nym-node/server.toml >/dev/null 2>&1 &)'
wg1 'for _ in $(seq 100); do ss -lun | grep -q ":51831 " && exit 0; sleep 0.2; done; exit 1'
wg1 'pkill iperf3; iperf3 -s -D'

printf '%-6s %-22s %9s %9s %9s %9s\n' profile path connect "down Mb/s" "up Mb/s" rtt
for profile in 3g 4g 5g poor; do
    shape "$profile"
    censor_off
    run_path "$profile" "vanilla WireGuard" 'wg-quick up wg0' 10.0.0.2 3
    censor_on
    run_path "$profile" "AmneziaWG 1.0 bridge" 'awg-up amneziawg-go awg10' 10.0.1.2 3
    run_path "$profile" "AmneziaWG 3.1 bridge" 'awg-up amneziawg-go awg31' 10.0.1.2 3
    for transport in quic tls ssh; do
        run_path "$profile" "$transport bridge" "$(bridge_setup "$transport")" 10.0.1.2 1
    done
done
unshape
censor_off

echo
# On a shaped link the network is the bottleneck, so the translator should match vanilla WireGuard.
result() { awk -F'|' -v p="$1" -v n="$2" -v c="$3" '$1 == p && $2 == n { print $c }' "$RESULTS"; }
for profile in 3g 4g 5g poor; do
    for path in "AmneziaWG 1.0 bridge" "AmneziaWG 3.1 bridge"; do
        for dir in download upload; do
            col=3
            [ "$dir" = upload ] && col=4
            a=$(result "$profile" "$path" "$col")
            b=$(result "$profile" "vanilla WireGuard" "$col")
            check "$profile $path $dir >= 80% of vanilla WireGuard (${a:-0} vs ${b:-0} Mbit/s)" \
                awk -v a="${a:-0}" -v b="${b:-0}" 'BEGIN { exit !(b > 0 && a >= 0.8 * b) }'
        done
    done
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "All network profile checks passed"
else
    echo "Network profile checks failed"
fi
exit "$FAILED"
