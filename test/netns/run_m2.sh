#!/usr/bin/env bash
# run_m2.sh - end-to-end check of multipath striping (milestone M2).
# Two shaped WANs (duo profile: 50 Mbit + 30 Mbit); a single TCP flow
# through the tunnel must beat the best single link.
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
PSK="m2-test-psk"

cat > "$WORK/server.yaml" <<EOF
tunnel:
  interface: treccia0
  address: 10.200.0.1/24
  private_key: $SERVER_PRIV
  peer_public_key: $CLIENT_PUB
listen: ":51820"
control_psk: "$PSK"
dashboard:
  listen: 127.0.0.1:8081
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
dashboard:
  listen: 127.0.0.1:8080
EOF

# telemetry NS PORT LABEL: one compact line per second from the dashboard.
telemetry() {
    local ns=$1 port=$2 label=$3
    while true; do
        ip netns exec "$ns" curl -s "http://127.0.0.1:$port/api/metrics" | python3 -c "
import json, sys
try:
    m = json.load(sys.stdin)
except Exception:
    sys.exit(0)
paths = m.get('paths') or (m.get('sessions') or [{}])[0].get('paths', [])
r = m.get('reorder') or (m.get('sessions') or [{}])[0].get('reorder', {})
f = m.get('fec') or (m.get('sessions') or [{}])[0].get('fec')
ps = ' '.join(
    f\"p{p.get('id')}[up={int(p.get('up', False))} w={p.get('weight_mbps', 0):.1f}M cap={p.get('capacity_mbps', 0):.1f}M q={p.get('queue_ms', 0):.0f}ms loss={p.get('loss_pct', 0):.1f}% owd={p.get('owd_avg_ms', 0):.0f}ms]\"
    for p in paths)
fec = f\" fec={f['params']}/rec{f['recovered']}\" if f else ''
print(f\"[$label] {ps} reorder[del={r.get('Delivered',0)} late={r.get('Late',0)} to={r.get('TimedOut',0)} depth={r.get('Depth',0)}]{fec}\", flush=True)
" 2>/dev/null || true
        sleep 1
    done
}

ip netns exec tr-cloud "$BIN/treccia-server" -config "$WORK/server.yaml" ${VERBOSE:+-verbose} > /tmp/treccia-test-server.log 2>&1 &
SERVER_PID=$!
sleep 0.5
ip netns exec tr-router "$BIN/treccia-client" -config "$WORK/client.yaml" ${VERBOSE:+-verbose} > /tmp/treccia-test-client.log 2>&1 &
CLIENT_PID=$!
sleep 2

bps() { python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum_received']['bits_per_second'])"; }

echo "== baseline: single WAN1 (50 Mbit shaped) =="
iperf_srv
BASE=$(ip netns exec tr-router iperf3 -c 10.10.0.2 -B 10.11.1.2 -t "${DURATION:-5}" -J | bps)

echo "== bonded: single TCP flow through the tunnel (50+30 Mbit) =="
# -O 4 omits TCP slow start: the assertion measures sustained bonding,
# not the one-time ramp transient.
iperf_srv
telemetry tr-router 8080 client &
TEL1=$!
telemetry tr-cloud 8081 server &
TEL2=$!
BOND=$(ip netns exec tr-router iperf3 -c 10.200.0.1 -O 6 -t "${DURATION:-16}" -J | bps)
kill $TEL1 $TEL2 2>/dev/null || true

# The bonded flow must beat the best single link (50 Mbit shaped).
python3 - "$BASE" "$BOND" <<'PY'
import sys
base, bond = float(sys.argv[1]), float(sys.argv[2])
print(f"baseline={base/1e6:.1f} Mbit/s bonded={bond/1e6:.1f} Mbit/s gain={bond/base:.2f}x")
sys.exit(0 if bond > base * 1.05 else 1)
PY
echo "M2 OK: bonding beats the best single link"
