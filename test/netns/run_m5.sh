#!/usr/bin/env bash
# run_m5.sh - end-to-end check of adaptive FEC (milestone M5).
# 2% random loss is injected on both WANs (iptables statistic, so it works
# even where netem is unavailable). A bulk UDP stream is measured twice:
# with FEC disabled (expect ~2% end-to-end loss) and with FEC 10:2 forced
# (expect <0.3% residual loss).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

WORK=$(mktemp -d)
CLIENT_PID=""
SERVER_PID=""
cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 0.3
    ./topo.sh down >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

make -C "$ROOT" build >/dev/null
BIN=$ROOT/bin

./topo.sh up duo

# 2% random drop on the uplink of both WANs (wansim ingress from the router).
for n in 1 2; do
    ip netns exec tr-wansim iptables -A FORWARD -i "sim$n" \
        -m statistic --mode random --probability 0.02 -j DROP
done

SERVER_PRIV=$("$BIN/treccia-server" genkey)
CLIENT_PRIV=$("$BIN/treccia-client" genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | "$BIN/treccia-server" pubkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | "$BIN/treccia-client" pubkey)
PSK="m5-test-psk"

# fec_mode: "disabled: true" or "force: 10:2"
write_confs() {
    local fec_line=$1
    cat > "$WORK/server.yaml" <<EOF
tunnel:
  interface: treccia0
  address: 10.200.0.1/24
  private_key: $SERVER_PRIV
  peer_public_key: $CLIENT_PUB
listen: ":51820"
control_psk: "$PSK"
fec:
  $fec_line
EOF
    cat > "$WORK/client.yaml" <<EOF
tunnel:
  interface: treccia0
  address: 10.200.0.2/24
  private_key: $CLIENT_PRIV
  peer_public_key: $SERVER_PUB
server_addr: "10.10.0.2:51820"
control_psk: "$PSK"
fec:
  $fec_line
paths:
  - name: wan1
    bind: 10.11.1.2
  - name: wan2
    bind: 10.11.2.2
EOF
}

# run_stream LABEL -> prints loss percentage
run_stream() {
    ip netns exec tr-cloud "$BIN/treccia-server" -config "$WORK/server.yaml" > /tmp/treccia-test-server.log 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    ip netns exec tr-router "$BIN/treccia-client" -config "$WORK/client.yaml" > /tmp/treccia-test-client.log 2>&1 &
    CLIENT_PID=$!
    sleep 3
    ip netns exec tr-cloud iperf3 -s -D -1
    sleep 0.3
    ip netns exec tr-router iperf3 -c 10.200.0.1 -u -b 20M -l 1200 -t 10 -J > "$WORK/out.json"
    kill "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
    wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
    CLIENT_PID=""; SERVER_PID=""
    python3 -c "
import json
s = json.load(open('$WORK/out.json'))['end']['sum']
print(f\"{100.0*s['lost_packets']/s['packets']:.3f}\")"
}

echo "== FEC disabled (raw 2% loss per link) =="
write_confs "disabled: true"
RAW=$(run_stream)
echo "loss without FEC: ${RAW}%"

echo "== FEC forced 10:2 =="
write_confs "force: \"10:2\""
FEC=$(run_stream)
echo "loss with FEC 10:2: ${FEC}%"

python3 - "$RAW" "$FEC" <<'PY'
import sys
raw, fec = float(sys.argv[1]), float(sys.argv[2])
assert raw > 0.8, f"loss injection not effective ({raw}%)"
assert fec < 0.3, f"FEC residual loss too high: {fec}%"
print(f"M5 OK: FEC repaired {raw}% link loss down to {fec}%")
PY
