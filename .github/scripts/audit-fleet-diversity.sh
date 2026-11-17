#!/usr/bin/env bash
set -euo pipefail

: "${NODE_STATUS_API_URL:?NODE_STATUS_API_URL not set}"
: "${ZULIP_BOT_EMAIL:?ZULIP_BOT_EMAIL not set}"
: "${ZULIP_BOT_KEY:?ZULIP_BOT_KEY not set}"
: "${ZULIP_CHANNEL:?ZULIP_CHANNEL not set}"
: "${ZULIP_TOPIC:?ZULIP_TOPIC not set}"

MAX_SHARE="${MAX_SHARE:-0.5}"

echo "::add-mask::${ZULIP_BOT_KEY}"

send_zulip_message() {
    curl --fail --silent --request POST \
      --url https://windmill.nymte.ch/api/r/send_markdown_to_zulip \
      -u "${ZULIP_BOT_EMAIL}:${ZULIP_BOT_KEY}" \
      --header "X-Zulip-To: ${ZULIP_CHANNEL}" \
      --header "X-Zulip-Topic: ${ZULIP_TOPIC}" \
      --data "$1"
}

bridge_ips=$(curl --fail --silent "${NODE_STATUS_API_URL}/v2/gateways/skinny?size=1000&page=0" \
    | jq -r '.items[] | select(.bridges != null) | .self_described.host_information.ip_address[0]')

if [[ -z "$bridge_ips" ]]; then
    echo "no bridge-carrying nodes reported by node-status-api, nothing to audit"
    exit 0
fi

params_file=$(mktemp)
trap 'rm -f "$params_file"' EXIT

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    response=$(curl --fail --silent --max-time 5 "http://${ip}:8080/api/v1/bridges/client-params" 2>/dev/null) \
        || { echo "warn: ${ip} did not respond, skipping" >&2; continue; }
    if ! jq -e . >/dev/null 2>&1 <<< "$response"; then
        echo "warn: ${ip} returned invalid JSON, skipping" >&2
        continue
    fi
    printf '%s\n' "$response" >> "$params_file"
done <<< "$bridge_ips"

total=$(grep -c . "$params_file" || true)
if [[ "$total" -eq 0 ]]; then
    echo "no bridge nodes responded, nothing to audit"
    exit 0
fi

report=""
check_field() {
    local label="$1" jq_filter="$2"
    local top value count share
    local advertised_def='def advertised: (.transports_v2 // []) as $v2 | if ($v2|length) > 0 then $v2 else (.transports // []) end;'
    # Dedup within each node (one line) first, so a value repeated across that node's own
    # transports (e.g. the same host on both QUIC and TLS) counts once, not once per transport.
    top=$(while IFS= read -r line; do
        jq -r "${advertised_def} ${jq_filter}" <<< "$line" 2>/dev/null | sort -u
    done < "$params_file" | sort | uniq -c | sort -rn | head -1)
    count=$(echo "$top" | awk '{print $1}')
    value=$(echo "$top" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')
    [[ -z "$count" ]] && return
    # Compare the raw count against the threshold scaled by total, not a rounded share, so a
    # share just over MAX_SHARE (e.g. 51/101) isn't missed by display rounding (0.50).
    if awk -v c="$count" -v t="$total" -v m="$MAX_SHARE" 'BEGIN { exit !(c > m * t) }'; then
        share=$(awk -v c="$count" -v t="$total" 'BEGIN { printf "%.2f", c / t }')
        report="${report}- **${label}**: \`${value}\` shared by ${count}/${total} responding nodes (${share})\n"
    fi
}

check_field "SNI host" 'advertised[]?.args.host // empty'
check_field "listen port" 'advertised[]?.args.addresses[0]? | split(":") | last'
check_field "transport type" 'advertised[]?.transport_type // empty'

if [[ -n "$report" ]]; then
    message=$(printf '**Fleet diversity audit: threshold exceeded**\n\n%b' "$report")
    echo -e "$message"
    send_zulip_message "$message" || echo "warn: failed to send Zulip alert" >&2
    exit 1
fi

echo "fleet diversity within thresholds (${total} nodes responded)"
