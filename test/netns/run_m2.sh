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
sleep 2

bps() { python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum_received']['bits_per_second'])"; }

echo "== baseline: single WAN1 (50 Mbit shaped) =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
BASE=$(ip netns exec tr-router iperf3 -c 10.10.0.2 -B 10.11.1.2 -t "${DURATION:-5}" -J | bps)

echo "== bonded: single TCP flow through the tunnel (50+30 Mbit) =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
BOND=$(ip netns exec tr-router iperf3 -c 10.200.0.1 -t "${DURATION:-5}" -J | bps)

# The bonded flow must beat the best single link (50 Mbit shaped).
python3 - "$BASE" "$BOND" <<'PY'
import sys
base, bond = float(sys.argv[1]), float(sys.argv[2])
print(f"baseline={base/1e6:.1f} Mbit/s bonded={bond/1e6:.1f} Mbit/s gain={bond/base:.2f}x")
sys.exit(0 if bond > base * 1.05 else 1)
PY
echo "M2 OK: bonding beats the best single link"
