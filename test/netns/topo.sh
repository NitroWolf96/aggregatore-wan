#!/usr/bin/env bash
# topo.sh - emulated multi-WAN topology for Treccia integration tests.
#
#   lan ── router ══(wan1/wan2/wan3 + netem)══ wansim ── cloud
#
# The router namespace plays the Treccia client (multi-homed on up to three
# WANs), wansim shapes each link with tc netem and routes everything to the
# cloud namespace, which plays the aggregation server ("public" IP 10.10.0.2).
#
# Usage:
#   sudo ./topo.sh up [profile]     create everything (default profile: mixed)
#   sudo ./topo.sh down             tear everything down (idempotent)
#   sudo ./topo.sh profile NAME     re-apply a netem profile at runtime
#   sudo ./topo.sh status           show namespaces, links and qdiscs
#   sudo ./topo.sh exec NS CMD...   run CMD in namespace NS (lan|router|wansim|cloud)
#
# Profiles (delay is one-way, applied on both directions of each link):
#   mixed  wan1=ftth 200mbit/5ms/0%  wan2=lte 40mbit/45ms±10/0.5%  wan3=lte 20mbit/70ms±20/2%
#   clean  all three links 100mbit/10ms/0%
#   duo    wan1=50mbit/20ms/0%  wan2=30mbit/60ms/0%  wan3 down

set -euo pipefail

NS_PREFIX=tr
LAN=$NS_PREFIX-lan
ROUTER=$NS_PREFIX-router
WANSIM=$NS_PREFIX-wansim
CLOUD=$NS_PREFIX-cloud
NWAN=3

nsx() { ip netns exec "$@"; }

die() { echo "topo.sh: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo)"

# apply_netem IFACE NS RATE DELAY JITTER LOSS
# Falls back to plain tbf rate limiting when the kernel lacks sch_netem
# (common in containers); delay/loss emulation then requires a CI runner.
apply_netem() {
    local iface=$1 ns=$2 rate=$3 delay=$4 jitter=$5 loss=$6
    if ! nsx "$ns" tc qdisc replace dev "$iface" root netem \
        rate "$rate" delay "$delay" "$jitter" loss random "$loss" 2>/dev/null; then
        echo "warn: netem unavailable, rate-only shaping on $ns/$iface" >&2
        nsx "$ns" tc qdisc replace dev "$iface" root tbf \
            rate "$rate" burst 64kbit latency 100ms
    fi
}

# link_profile N RATE DELAY JITTER LOSS - shape wanN in both directions
link_profile() {
    local n=$1 rate=$2 delay=$3 jitter=$4 loss=$5
    apply_netem "wan$n" "$ROUTER" "$rate" "$delay" "$jitter" "$loss"
    apply_netem "sim$n" "$WANSIM" "$rate" "$delay" "$jitter" "$loss"
    nsx "$ROUTER" ip link set "wan$n" up
    nsx "$WANSIM" ip link set "sim$n" up
}

profile() {
    case "$1" in
    mixed)
        link_profile 1 200mbit 5ms 0ms 0%
        link_profile 2 40mbit 45ms 10ms 0.5%
        link_profile 3 20mbit 70ms 20ms 2%
        ;;
    clean)
        link_profile 1 100mbit 10ms 0ms 0%
        link_profile 2 100mbit 10ms 0ms 0%
        link_profile 3 100mbit 10ms 0ms 0%
        ;;
    duo)
        link_profile 1 50mbit 20ms 0ms 0%
        link_profile 2 30mbit 60ms 0ms 0%
        nsx "$ROUTER" ip link set wan3 down
        ;;
    *) die "unknown profile: $1" ;;
    esac
    echo "profile $1 applied"
}

up() {
    local prof=${1:-mixed}
    down_quiet

    for ns in "$LAN" "$ROUTER" "$WANSIM" "$CLOUD"; do
        ip netns add "$ns"
        nsx "$ns" ip link set lo up
    done

    # lan <-> router
    ip link add lan0 netns "$LAN" type veth peer name lanr netns "$ROUTER"
    nsx "$LAN" ip addr add 10.99.0.2/24 dev lan0
    nsx "$ROUTER" ip addr add 10.99.0.1/24 dev lanr
    nsx "$LAN" ip link set lan0 up
    nsx "$ROUTER" ip link set lanr up
    nsx "$LAN" ip route add default via 10.99.0.1

    # router <-> wansim: three shaped WAN links
    for n in $(seq 1 $NWAN); do
        ip link add "wan$n" netns "$ROUTER" type veth peer name "sim$n" netns "$WANSIM"
        nsx "$ROUTER" ip addr add "10.11.$n.2/24" dev "wan$n"
        nsx "$WANSIM" ip addr add "10.11.$n.1/24" dev "sim$n"
        nsx "$ROUTER" ip link set "wan$n" up
        nsx "$WANSIM" ip link set "sim$n" up
        # Per-WAN routing table: reach the cloud from this WAN's source address.
        nsx "$ROUTER" ip route add 10.10.0.0/24 via "10.11.$n.1" dev "wan$n" table "$((100 + n))"
        nsx "$ROUTER" ip rule add from "10.11.$n.2" lookup "$((100 + n))"
    done

    # wansim <-> cloud ("public" internet side)
    ip link add up0 netns "$WANSIM" type veth peer name eth0 netns "$CLOUD"
    nsx "$WANSIM" ip addr add 10.10.0.1/24 dev up0
    nsx "$CLOUD" ip addr add 10.10.0.2/24 dev eth0
    nsx "$WANSIM" ip link set up0 up
    nsx "$CLOUD" ip link set eth0 up
    nsx "$CLOUD" ip route add 10.11.0.0/16 via 10.10.0.1

    nsx "$WANSIM" sysctl -qw net.ipv4.ip_forward=1
    nsx "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
    # MTU 1428 on WAN links, like a typical 4G APN, so the tunnel MTU math is honest.
    for n in $(seq 1 $NWAN); do
        nsx "$ROUTER" ip link set "wan$n" mtu 1428
        nsx "$WANSIM" ip link set "sim$n" mtu 1428
    done

    profile "$prof"
    echo "topology up (server: 10.10.0.2, router WAN sources: 10.11.{1,2,3}.2)"
}

down_quiet() {
    for ns in "$LAN" "$ROUTER" "$WANSIM" "$CLOUD"; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

status() {
    for ns in "$LAN" "$ROUTER" "$WANSIM" "$CLOUD"; do
        if ip netns list | grep -qw "$ns"; then
            echo "== $ns =="
            nsx "$ns" ip -brief addr
            nsx "$ns" tc qdisc show 2>/dev/null | grep netem || true
        else
            echo "== $ns == (absent)"
        fi
    done
}

case "${1:-}" in
up) up "${2:-mixed}" ;;
down) down_quiet; echo "topology down" ;;
profile) [ $# -ge 2 ] || die "profile NAME"; profile "$2" ;;
status) status ;;
exec)
    [ $# -ge 3 ] || die "exec NS CMD..."
    ns=$2; shift 2
    nsx "$NS_PREFIX-$ns" "$@"
    ;;
*) die "usage: topo.sh up|down|profile|status|exec" ;;
esac
