#!/usr/bin/env bash
# run_m1.sh - end-to-end check of the single-path tunnel (milestone M1).
# Builds the binaries, brings the topology up, starts server+client, then
# pings and runs iperf3 through the tunnel over wan1.
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

./topo.sh up "${PROFILE:-clean}"

# Keys.
SERVER_PRIV=$("$BIN/treccia-server" genkey)
CLIENT_PRIV=$("$BIN/treccia-client" genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | "$BIN/treccia-server" pubkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | "$BIN/treccia-client" pubkey)
PSK="m1-test-psk"

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
EOF

ip netns exec tr-cloud "$BIN/treccia-server" -config "$WORK/server.yaml" ${VERBOSE:+-verbose} &
SERVER_PID=$!
sleep 0.5
ip netns exec tr-router "$BIN/treccia-client" -config "$WORK/client.yaml" ${VERBOSE:+-verbose} &
CLIENT_PID=$!
sleep 1.5

echo "== ping through the tunnel =="
ip netns exec tr-router ping -c 3 -i 0.3 -W 2 10.200.0.1

echo "== iperf3 upload through the tunnel =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
ip netns exec tr-router iperf3 -c 10.200.0.1 -t "${DURATION:-5}" -f m

echo "== iperf3 download through the tunnel =="
ip netns exec tr-cloud iperf3 -s -D -1
sleep 0.3
ip netns exec tr-router iperf3 -c 10.200.0.1 -t "${DURATION:-5}" -f m -R

echo "M1 OK"
