#!/bin/bash
# Commands in single quotes expand inside the containers.
# shellcheck disable=SC2016,SC2329
# Long-distance gateway paths for the AmneziaWG translator. The translator sits on the first hop
# (user -> entry), so tc netem on eth0 sets that hop; the entry -> exit hop is ordinary WireGuard,
# emulated as extra delay on the tunnel interfaces of both ends (traffic already translated).
# Needs Docker; reuses the awg-lab.sh environment.
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

# first-hop one-way delay, second-hop one-way delay (user in Germany in every scenario)
scenario() {
    case "$1" in
        de-de-de) echo "5ms 5ms" ;;
        de-es-au) echo "20ms 150ms" ;;
        de-au-es) echo "150ms 150ms" ;;
    esac
}
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

first_hop() { # one-way delay on the outer link, 100 Mbit/s each way
    for c in wg0 wg1; do
        docker exec "$c" tc qdisc replace dev eth0 root netem rate 100mbit delay "$1" 2ms limit 100000
    done
}
second_hop() { # client tunnel iface, server tunnel iface, one-way delay
    wg0 "tc qdisc replace dev $1 root netem delay $3 limit 100000"
    wg1 "tc qdisc replace dev $2 root netem delay $3 limit 100000"
}
clear_shaping() {
    for c in wg0 wg1; do
        docker exec "$c" bash -c 'for i in eth0 wg1 wg-q1; do tc qdisc del dev $i root 2>/dev/null; done; true'
    done
}

connect_time() { # setup, peer
    local start
    start=$(date +%s.%N)
    wg0 "$1" >/dev/null 2>&1
    wg0 "for _ in \$(seq 60); do ping -c 1 -W 2 $2 >/dev/null && exit 0; done; exit 1" || { echo fail; return; }
    awk -v s="$start" -v e="$(date +%s.%N)" 'BEGIN { printf "%.1f", e - s }'
}
# Long round trips need time to ramp up, and single runs swing widely: median of three 20 s runs.
mbit() {
    local runs=()
    for _ in 1 2 3; do
        runs+=("$(wg0 "iperf3 -c $1 -t 20 -O 5 -f m $2 2>/dev/null | awk '/receiver/ {print \$7}'")")
    done
    printf '%s\n' "${runs[@]:-0}" | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'
}
rtt() { wg0 "ping -c 10 -i 0.3 -q $1 | awk -F/ '/rtt/ {print \$5}'"; }

run_path() { # scenario, name, setup, peer, client iface, server iface
    local t down up r second
    read -r _ second <<<"$(scenario "$1")"
    t=$(connect_time "$3" "$4")
    if [ "$t" = fail ]; then
        fail "$1 $2: connects"
        all_down
        return
    fi
    second_hop "$5" "$6" "$second"
    down=$(mbit "$4" -R)
    up=$(mbit "$4" "")
    r=$(rtt "$4")
    echo "$1|$2|${down:-0}|${up:-0}|$t" >>"$RESULTS"
    printf '%-9s %-22s %7s s %9s %9s %10s ms\n' "$1" "$2" "$t" "${down:-0}" "${up:-0}" "${r:-n/a}"
    wg1 "tc qdisc del dev $6 root 2>/dev/null; true"
    all_down
}

docker compose up -d --build
# Gateways get this from the package's sysctl file; the containers share the Docker VM's kernel.
docker run --rm --privileged --net=host --entrypoint sysctl test-env-wg1 -q -w net.core.rmem_max=4194304
all_down
clear_shaping
wg1 'pgrep -x nym-bridge >/dev/null || (nym-bridge -c /etc/nym/default-nym-node/server.toml >/dev/null 2>&1 &)'
wg1 'for _ in $(seq 100); do ss -lun | grep -q ":51831 " && exit 0; sleep 0.2; done; exit 1'
wg1 'pkill iperf3; iperf3 -s -D'

printf '%-9s %-22s %9s %9s %9s %13s\n' scenario path connect "down Mb/s" "up Mb/s" "inner rtt"
for s in de-de-de de-es-au de-au-es; do
    read -r first _ <<<"$(scenario "$s")"
    first_hop "$first"
    censor_off
    run_path "$s" "vanilla WireGuard" 'wg-quick up wg0' 10.0.0.2 wg0 wg1
    run_path "$s" "amneziawg-go base mode" 'awg-up amneziawg-go base' 10.0.0.2 awg0 wg1
    censor_on
    run_path "$s" "AmneziaWG 1.0 bridge" 'awg-up amneziawg-go awg10' 10.0.1.2 awg0 wg-q1
    run_path "$s" "AmneziaWG 3.1 bridge" 'awg-up amneziawg-go awg31' 10.0.1.2 awg0 wg-q1
    run_path "$s" "quic bridge" "pkill client-udp; setsid client-udp --config /etc/nym/default-nym-node/client_quic.toml </dev/null >/dev/null 2>&1 & sleep 1; wg-quick up wg-q0" 10.0.1.2 wg-q0 wg-q1
done
clear_shaping
censor_off

echo
# The apps run amneziawg-go in every mode, so base mode is the baseline users have today; kernel
# WireGuard is shown for reference only.
result() { awk -F'|' -v s="$1" -v n="$2" -v c="$3" '$1 == s && $2 == n { print $c }' "$RESULTS"; }
for s in de-de-de de-es-au de-au-es; do
    for path in "AmneziaWG 1.0 bridge" "AmneziaWG 3.1 bridge"; do
        a=$(result "$s" "$path" 3)
        b=$(result "$s" "amneziawg-go base mode" 3)
        check "$s $path download >= 80% of base mode (${a:-0} vs ${b:-0} Mbit/s)" \
            awk -v a="${a:-0}" -v b="${b:-0}" 'BEGIN { exit !(b > 0 && a >= 0.8 * b) }'
        a=$(result "$s" "$path" 5)
        b=$(result "$s" "amneziawg-go base mode" 5)
        check "$s $path connects within 1 s of base mode (${a:-n/a} vs ${b:-n/a} s)" \
            awk -v a="${a:-99}" -v b="${b:-0}" 'BEGIN { exit !(a <= b + 1) }'
    done
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "All geography checks passed"
else
    echo "Geography checks failed"
fi
exit "$FAILED"
