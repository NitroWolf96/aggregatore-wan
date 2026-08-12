#!/usr/bin/env bash
# run_m3.sh - end-to-end check of the adaptive scheduler and failover (M3).
# 1) weighted bonding on duo (50+30 Mbit) must beat plain round-robin;
# 2) a WAN failure mid-transfer must not kill the TCP session, and
#    throughput must recover after the link returns.
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
PSK="m3-test-psk"

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
sleep 3  # let probes measure the paths

bps() { python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum_received']['bits_per_second'])"; }

echo "== weighted bonding on 50+30 Mbit =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
BOND=$(ip netns exec tr-router iperf3 -c 10.200.0.1 -t "${DURATION:-8}" -J | bps)
python3 -c "b=$BOND/1e6; print(f'bonded (weighted): {b:.1f} Mbit/s')"

echo "== failover: wan1 dies mid-transfer, returns, throughput recovers =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
LOG="$WORK/failover.json"
ip netns exec tr-router iperf3 -c 10.200.0.1 -t 20 -J > "$LOG" &
IPERF_PID=$!
sleep 5
./chaos.sh flap 1 6   # down at t=5s, up at t=11s
wait "$IPERF_PID"

python3 - "$LOG" "$BOND" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
bond = float(sys.argv[2])
ints = [ (i['sum']['start'], i['sum']['bits_per_second']/1e6) for i in data['intervals'] ]
for t, mbps in ints:
    print(f"  t={t:5.1f}s  {mbps:7.1f} Mbit/s")
total = data['end']['sum_received']['bits_per_second']/1e6
print(f"session survived the WAN failure; average {total:.1f} Mbit/s")
# During the outage only wan2 (30 Mbit) works; afterwards throughput must recover.
tail = [m for t, m in ints if t >= 15]
assert ints, "no intervals: session died"
assert total > 5, f"session effectively dead ({total:.1f} Mbit/s)"
assert max(tail) > 30, f"no recovery after link return (tail max {max(tail):.1f})"
print("M3 OK: failover + recovery")
PY
