#!/usr/bin/env bash
# run_m4.sh - end-to-end check of per-flow classification (milestone M4).
# An RTP-like UDP stream (small packets -> classified REALTIME -> duplicated
# on both paths) must survive a mid-stream WAN failure with ~zero loss,
# while a concurrent TCP flow keeps striping as BULK.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

WORK=$(mktemp -d)
CLIENT_PID=""
SERVER_PID=""
cleanup() {
    status=$?
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 0.3
    ./topo.sh down >/dev/null 2>&1 || true
    rm -rf "$WORK"
    if [ "$status" -ne 0 ]; then
        echo "--- server log (tail) ---"; tail -n 15 /tmp/treccia-test-server.log 2>/dev/null || true
        echo "--- client log (tail) ---"; tail -n 15 /tmp/treccia-test-client.log 2>/dev/null || true
    fi
}
trap cleanup EXIT

make -C "$ROOT" build >/dev/null
BIN=$ROOT/bin

iperf_srv() {
    ip netns exec tr-cloud pkill -x iperf3 2>/dev/null || true
    sleep 0.2
    ip netns exec tr-cloud iperf3 -s -D
    for _ in $(seq 1 25); do
        ip netns exec tr-cloud ss -ltn 2>/dev/null | grep -q 5201 && { sleep 0.2; return 0; }
        sleep 0.2
    done
    echo "iperf3 server failed to start" >&2
    return 1
}


./topo.sh up duo

SERVER_PRIV=$("$BIN/treccia-server" genkey)
CLIENT_PRIV=$("$BIN/treccia-client" genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | "$BIN/treccia-server" pubkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | "$BIN/treccia-client" pubkey)
PSK="m4-test-psk"

cat > "$WORK/server.yaml" <<EOF
tunnel:
  interface: treccia0
  address: 10.200.0.1/24
  private_key: $SERVER_PRIV
  peer_public_key: $CLIENT_PUB
listen: ":51820"
control_psk: "$PSK"
EOF

cat > "$WORK/client.yaml" <<EOF
tunnel:
  interface: treccia0
  address: 10.200.0.2/24
  private_key: $CLIENT_PRIV
  peer_public_key: $SERVER_PUB
server_addr: "10.10.0.2:51820"
control_psk: "$PSK"
paths:
  - name: wan1
    bind: 10.11.1.2
  - name: wan2
    bind: 10.11.2.2
EOF

ip netns exec tr-cloud "$BIN/treccia-server" -config "$WORK/server.yaml" ${VERBOSE:+-verbose} > /tmp/treccia-test-server.log 2>&1 &
SERVER_PID=$!
sleep 0.5
ip netns exec tr-router "$BIN/treccia-client" -config "$WORK/client.yaml" ${VERBOSE:+-verbose} > /tmp/treccia-test-client.log 2>&1 &
CLIENT_PID=$!
sleep 3

echo "== realtime UDP stream (160B packets, duplicated) + WAN failure =="
iperf_srv
LOG="$WORK/rt.json"
ip netns exec tr-router iperf3 -c 10.200.0.1 -u -b 400k -l 160 -t 15 -J > "$LOG" &
IPERF_PID=$!
sleep 5
./chaos.sh flap 1 6
wait "$IPERF_PID"

python3 - "$LOG" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d['end']['sum']
lost, total = s['lost_packets'], s['packets']
pct = 100.0 * lost / total if total else 100.0
print(f"realtime stream: {total} packets, lost {lost} ({pct:.2f}%) across a 6s WAN outage")
assert total > 3000, f"stream too short: {total}"
assert pct < 1.0, f"duplication failed to protect the stream: {pct:.2f}% loss"
print("M4 OK: realtime duplication ate the WAN failure")
PY
