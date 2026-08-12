# Treccia

*Braid your WAN links into one connection.*

**Treccia** (Italian for *braid*) is a self-hosted WAN bonding system: it
aggregates multiple internet connections (FTTH + 4G/5G, multiple SIMs,
Starlink + LTE, ...) into a single encrypted tunnel with **per-packet
scheduling** — so even a single TCP flow can use the bandwidth of all
links combined — plus instant failover and loss protection for real-time
traffic.

Measured by CI on the emulated rig (`test/netns`: tc netem, 50+30 Mbit
links with asymmetric 40/120ms RTTs):

| Scenario | Result |
|---|---|
| Single TCP flow, sustained | **63.7 Mbit/s** vs 45.7 on the best link alone (**1.40x**) |
| One WAN dies for 6s mid-transfer | session survives on the other link, throughput recovers after it returns |
| RTP-like stream through the same 6s outage | **0 of 4688 packets lost** (realtime duplication) |
| 2% random loss per link | 1.95% end-to-end loss → **0.024%** with FEC 10:2 |

## How it works

One Go binary per side. The client owns a TUN interface and embeds
WireGuard (userspace); the multipath engine underneath schedules the
encrypted packets across N WAN sockets toward a single UDP port on the
server, which resequences, repairs and decrypts them, then NATs to the
internet. Traffic classes get different strategies, per flow:

- **Bulk** (downloads, uploads) — striped in proportion to each link's
  measured capacity, resequenced in an adaptive reorder buffer, protected
  by adaptive Reed-Solomon FEC when links are lossy. A LEDBAT-style
  queueing-delay discount plus an ingress AQM keep bottleneck queues
  short, so bufferbloat on one link can't poison the bonded flow.
- **Realtime** (VoIP, gaming, small-packet UDP) — duplicated on the two
  lowest-latency links; WireGuard's anti-replay dedups the copies. A dead
  link costs zero packets.
- **Interactive** (DNS, SSH, acks, WG handshakes) — pinned to the
  lowest-latency link, never waits on striping gaps.

No kernel modules, no custom firmware, no patched kernels: any Linux with
`/dev/net/tun` (mini PC, Raspberry Pi, VPS, container). Everything is
client-initiated over one UDP port, so CGNAT on the 4G/5G side is fine.
Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Quickstart

### 1. Server (the aggregation endpoint)

Any Linux box with a public IP works. For a **zero-cost endpoint on
Oracle Cloud Always Free** (2 ARM OCPUs, 12 GB, 10 TB egress/month):

```sh
cd deploy/terraform/oracle
terraform init
# fill terraform.tfvars (tenancy/user OCIDs, region, ssh key, client pubkey)
./retry-apply.sh          # rides out Oracle's "out of capacity"
```

The instance builds treccia from source, generates its keys, configures
NAT and starts systemd. Outputs print the server IP and the command that
reads the server public key.

Manual/Docker alternative:

```sh
docker run -d --name treccia --cap-add NET_ADMIN --device /dev/net/tun \
  -p 51820:51820/udp -v /etc/treccia:/etc/treccia \
  ghcr.io/nitrowolf96/aggregatore-wan/treccia:latest
```

### 2. Keys and config

```sh
treccia-client genkey | tee client.key | treccia-client pubkey   # and same on the server
cp configs/client.example.yaml /etc/treccia/client.yaml          # then edit
```

Both sides share a `control_psk` (any long random string) and exchange
WireGuard public keys. See `configs/*.example.yaml` — they are commented.

### 3. Client

One `paths:` entry per WAN, each with a source IP on that WAN. Policy
routing must steer each source out of its own WAN (most multi-WAN setups
already have this; otherwise):

```sh
ip route add default via <wan2_gw> dev <wan2_if> table 101
ip rule add from <wan2_src_ip> lookup 101
```

Then:

```sh
sudo treccia-client -config /etc/treccia/client.yaml
```

Route traffic into the tunnel per-host (`ip route add ... dev treccia0`)
or wholesale (`routes: ["0.0.0.0/1", "128.0.0.0/1"]` in the config).
The live dashboard is at `http://127.0.0.1:8080` (per-path RTT/loss/
capacity, weight shares, reorder and FEC counters, throughput chart).

## Development

```sh
make build test-race fuzz          # unit level
sudo test/netns/topo.sh up         # emulated 3-WAN rig (tc netem)
sudo test/netns/run_m3.sh          # e.g. the failover/recovery suite
```

The five end-to-end suites (`run_m1..m5.sh`) build the daemons, bring up
the namespace rig, and assert throughput, failover, duplication and FEC
behavior. CI runs all of them on every push.

## Status & roadmap

Working today: multipath striping with adaptive weights, instant
failover/recovery, per-flow classification, realtime duplication,
adaptive FEC, live dashboard, Oracle/Docker deploy.

Planned: per-packet data-plane auth (SipHash), tunnel-side pacing to
smooth the TCP slow-start transient, netlink-driven path hot-plug for
interfaces unknown at startup, batched I/O (`sendmmsg`) for multi-gigabit
rates, an OpenWrt package, and an SRTLA-compatible receiver for
IRL-streaming setups.

## License

MIT
