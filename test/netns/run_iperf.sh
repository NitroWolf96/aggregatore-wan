#!/usr/bin/env bash
# run_iperf.sh - throughput smoke test across the emulated topology.
# Requires: topo.sh up, iperf3 installed, treccia running (or use --raw to
# measure a single raw WAN path without the tunnel, as a baseline).
#
#   sudo ./run_iperf.sh            iperf3 through the tunnel (lan -> cloud tunnel IP)
#   sudo ./run_iperf.sh --raw N    baseline: iperf3 from router via wanN to cloud
#   sudo ./run_iperf.sh --udp      UDP mode with loss report

set -euo pipefail
cd "$(dirname "$0")"

DURATION=${DURATION:-10}
TUNNEL_SERVER_IP=${TUNNEL_SERVER_IP:-10.200.0.1}

mode=tunnel
udp=""
rawn=1
while [ $# -gt 0 ]; do
    case "$1" in
    --raw) mode=raw; rawn=${2:-1}; shift ;;
    --udp) udp="-u -b 0" ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

./topo.sh exec cloud pkill -x iperf3 2>/dev/null || true
sleep 0.3
./topo.sh exec cloud iperf3 -s -D
sleep 0.5

case "$mode" in
raw)
    echo "== baseline via wan$rawn =="
    ./topo.sh exec router iperf3 -c 10.10.0.2 -B "10.11.$rawn.2" -t "$DURATION" $udp
    ;;
tunnel)
    echo "== through the tunnel =="
    ./topo.sh exec lan iperf3 -c "$TUNNEL_SERVER_IP" -t "$DURATION" $udp
    ;;
esac

./topo.sh exec cloud pkill -x iperf3 2>/dev/null || true
