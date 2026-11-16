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
    curl --fail --silent --max-time 5 "http://${ip}:8080/api/v1/bridges/client-params" \
        >> "$params_file" 2>/dev/null || echo "warn: ${ip} did not respond, skipping" >&2
    echo >> "$params_file"
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
    top=$(jq -r "$jq_filter" "$params_file" 2>/dev/null \
        | sort | uniq -c | sort -rn | head -1)
    count=$(echo "$top" | awk '{print $1}')
    value=$(echo "$top" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')
    [[ -z "$count" ]] && return
    share=$(awk -v c="$count" -v t="$total" 'BEGIN { printf "%.2f", c / t }')
    if awk -v s="$share" -v m="$MAX_SHARE" 'BEGIN { exit !(s > m) }'; then
        report="${report}- **${label}**: \`${value}\` shared by ${count}/${total} responding nodes (${share})\n"
    fi
}

check_field "SNI host" '.transports_v2[]?.args.host // empty'
check_field "listen port" '.transports_v2[]?.args.addresses[0]? | split(":") | last'
check_field "transport type" '.transports_v2[]?.transport_type // empty'

if [[ -n "$report" ]]; then
    message=$(printf '**Fleet diversity audit: threshold exceeded**\n\n%b' "$report")
    echo -e "$message"
    send_zulip_message "$message" || echo "warn: failed to send Zulip alert" >&2
    exit 1
fi

echo "fleet diversity within thresholds (${total} nodes responded)"
