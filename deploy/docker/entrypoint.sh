#!/bin/sh
# Container entrypoint: enables forwarding and NAT of the tunnel subnet
# (TRECCIA_NAT=0 disables), then runs the daemon.
set -e

if [ "${TRECCIA_NAT:-1}" = "1" ]; then
    sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
    SUBNET=${TRECCIA_SUBNET:-10.200.0.0/24}
    OUT_IF=${TRECCIA_OUT_IF:-$(ip route show default | awk '/default/ {print $5; exit}')}
    if [ -n "$OUT_IF" ]; then
        iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$OUT_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$OUT_IF" -j MASQUERADE
    fi
fi

exec "$@"
