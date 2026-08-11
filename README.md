# Treccia

*Braid your WAN links into one connection.*

**Treccia** (Italian for *braid*) is a self-hosted WAN bonding system: it
aggregates multiple internet connections (FTTH + 4G/5G, multiple SIMs,
Starlink + LTE, ...) into a single tunnel with **per-packet scheduling**, so
even a single TCP flow can use the bandwidth of all links combined — plus
instant failover and loss protection for real-time traffic.

> ⚠️ **Work in progress.** The project is being built milestone by milestone;
> see the roadmap below.

## Why another bonding tool?

Every maintained open-source option today is missing something:

- Per-flow load balancers (`mwan3`, dispatch proxies) never speed up a single flow.
- `engarde` only *duplicates* packets across links (reliability, no aggregation).
- OpenMPTCProuter does true bonding, but requires a dedicated router firmware,
  patched kernels and a KVM-only VPS — and MPTCP covers TCP only.
- The classic lightweight packet-level bonders (mlvpn, glorytun, vtrunkd) are
  all unmaintained, and none of them ever had working reordering or automatic
  link weighting.
- Speedify proves the demand, but it is closed-source and subscription-based.

Treccia aims to be the modern, embeddable, zero-cost answer:

- **One Go binary** per side (`treccia-client`, `treccia-server`), embedded
  WireGuard (userspace `wireguard-go`) — no kernel modules, no firmware to
  flash, runs on any Linux box (mini PC, Raspberry Pi, container).
- **Per-packet multipath engine under WireGuard**: the engine schedules
  encrypted UDP datagrams across N links, with sequence numbers, an adaptive
  reorder buffer and automatic per-link estimation (RTT, loss, capacity).
- **Class-aware scheduling**: bulk flows are striped for throughput,
  real-time flows are duplicated on the two best links, interactive flows
  stick to the lowest-latency path. Adaptive Reed-Solomon FEC protects lossy
  links without duplication cost.
- **Zero-cost server**: designed to fit the Oracle Cloud Always Free ARM
  shape (2 OCPU / 12 GB, 10 TB egress/month), with Terraform + cloud-init
  automation included. Any €4/month VPS works too.
- **CGNAT-friendly**: everything is client-initiated over a single UDP port;
  per-path roaming like WireGuard.

## Architecture at a glance

```
             ┌───────────────────────────── client box ─────────────────────────────┐
 LAN ──► TUN treccia0 ──► classifier ──► WireGuard (userspace) ──► multipath engine │
             │                                     scheduler / FEC / duplication    │
             └──────────────┬──────────────┬──────────────┬─────────────────────────┘
                          WAN1(fiber)    WAN2(4G)       WAN3(5G)
                            └──────────────┴──────┬───────┘
                                                  ▼ single UDP port
             ┌────────────────────────────── VPS (free tier) ──────────────────────┐
             │ multipath engine (reorder/dedup/FEC) ──► WireGuard ──► NAT ──► internet
             └─────────────────────────────────────────────────────────────────────┘
```

## Roadmap

- [x] M0 — scaffold, wire protocol (+fuzz), netns test topology
- [ ] M1 — single-path tunnel (embedded wireguard-go, HELLO handshake)
- [ ] M2 — multipath striping + reorder buffer
- [ ] M3 — link estimation, adaptive WRR scheduler, instant failover
- [ ] M4 — per-flow classification + real-time duplication
- [ ] M5 — adaptive Reed-Solomon FEC
- [ ] M6 — live web dashboard
- [ ] M7 — Docker multi-arch + Terraform for Oracle Cloud free tier
- [ ] M8 — hardening, docs, quickstart

## Development

```sh
make build        # build both binaries into ./bin
make test-race    # unit tests
make fuzz         # fuzz the wire protocol
sudo test/netns/topo.sh up      # emulated 3-WAN topology (tc netem)
sudo test/netns/topo.sh down
```

## License

MIT
