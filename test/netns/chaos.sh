#!/usr/bin/env bash
# chaos.sh - flap WAN links while traffic is running.
#   sudo ./chaos.sh flap N SECONDS   take wanN down for SECONDS, then back up
#   sudo ./chaos.sh cycle            continuous random flapping until killed
set -euo pipefail
cd "$(dirname "$0")"

flap() {
    local n=$1 secs=$2
    echo "chaos: wan$n down for ${secs}s"
    ip netns exec tr-router ip link set "wan$n" down
    sleep "$secs"
    ip netns exec tr-router ip link set "wan$n" up
    # Link-down flushes the policy table route; a real router's DHCP client
    # or netifd reinstalls it on link-up, so the emulation does too.
    ip netns exec tr-router ip route replace 10.10.0.0/24 \
        via "10.11.$n.1" dev "wan$n" table "$((100 + n))"
    echo "chaos: wan$n back up"
}

case "${1:-}" in
flap) flap "${2:?wan number}" "${3:?seconds}" ;;
cycle)
    while true; do
        n=$(( (RANDOM % 2) + 1 ))
        flap "$n" $(( (RANDOM % 5) + 2 ))
        sleep $(( (RANDOM % 8) + 4 ))
    done
    ;;
*) echo "usage: chaos.sh flap N SECONDS | cycle" >&2; exit 1 ;;
esac
