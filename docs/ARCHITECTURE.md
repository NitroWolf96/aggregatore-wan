# Treccia architecture

Treccia bonds multiple WAN links into one encrypted tunnel with
**per-packet scheduling**: a single TCP flow can use the bandwidth of all
links combined, latency-sensitive traffic is protected by duplication, and
loss is repaired by forward error correction — each flow getting the
strategy that fits it.

## The one decision everything follows from

Treccia embeds **wireguard-go as a library** instead of sitting beside
kernel WireGuard:

- `internal/wgbridge.TunShim` wraps the TUN device, so every outbound
  plaintext IP packet is seen (and classified) *before* encryption;
- `internal/wgbridge.EngineBind` replaces the UDP socket WireGuard would
  own: `Send()` hands ciphertext to the multipath engine, and the receive
  path feeds it ciphertext the engine has already resequenced.

WireGuard believes it has one peer over one socket; underneath, the engine
owns N sockets (one per WAN) and decides, packet by packet, which link
each datagram leaves from. Crypto, replay protection and key management
stay entirely inside WireGuard — audited code, untouched. Two WireGuard
properties do double duty:

- **anti-replay** deduplicates the copies made for realtime traffic, free;
- **roaming** (newest authenticated source wins) means path addresses can
  change at any time without rekeying.

One consequence: everything runs in one userspace binary per side, on any
Linux with `/dev/net/tun` — no kernel modules, no custom firmware, and the
server fits in an unprivileged-ish container (`CAP_NET_ADMIN` + tun).

## Packet path

```
uplink (client -> server); the downlink is the same, mirrored
────────────────────────────────────────────────────────────
app → kernel routing → TUN treccia0 (MTU 1344)
  → TunShim: classify 5-tuple → correlator FIFO (class, expected ct len)
  → wireguard-go: ChaCha20-Poly1305
  → EngineBind.Send → ENGINE TX:
      class := correlator.Match(len(ct))
      BULK        → weighted stripe + global_seq + optional FEC group
      REALTIME    → duplicate on the 2 best-latency paths (same seq, DUP flag)
      INTERACTIVE → single best-latency path
      handshakes/keepalives → INTERACTIVE
  → wire framing (20/24B) → per-WAN UDP socket → internet

ENGINE RX (other side):
  DATA(bulk)     → per-path stats (loss/OWD) → FEC decoder copy → reorder
                   buffer (release in order, or after the adaptive hold)
  DATA(rt/inter) → bypass reorder, deliver immediately (WG dedups copies)
  FEC parity     → decoder; missing packets are rebuilt and re-injected
  → EngineBind.Deliver → wireguard-go decrypts → TUN → kernel (NAT on server)
```

## Design choices worth knowing about

**Correlation, not deep hooks.** wireguard-go preserves per-peer ordering
between TUN reads and `Send` calls, so a FIFO of `(class, expected
ciphertext length)` entries — `expected = 16 + pad16(pt) + 16` — maps each
outgoing datagram back to its flow class without patching wireguard-go.
Mismatches scan ahead a few entries (WG can drop packets internally when
queues fill) and fall back to BULK; hit/miss counters are on the dashboard.

**Two sequence spaces.** Only BULK packets consume the ordered
`global_seq` stream the reorder buffer releases; REALTIME/INTERACTIVE use
a separate free-running space and bypass the buffer entirely. If they
shared one space, every realtime packet delivered early would look like a
gap and stall bulk until the hold timer fired.

**Rate-proportional scheduling, not windows.** The scheduler
(`internal/sched`) is a smooth deficit-WRR: each path's share is its
measured delivery rate (BBR-style windowed max, `internal/pathmon`)
discounted by a loss factor, floored at 5% so weak paths keep being
measured. An earlier srtla-style window/in-flight scheduler collapsed in
testing whenever RTT ≪ the 50ms feedback interval (in-flight always looked
huge): srtla can afford windows because SRT acks per-packet; a general
tunnel cannot. The inner TCP/QUIC already provides end-to-end congestion
control — the tunnel's job is proportions and failover, and the reorder
buffer absorbs the latency spread.

**Failover is three mechanisms, not one.** (1) Socket write errors mark a
path down instantly (cable pulled). (2) Three lost probes (100ms cadence)
mark it down within ~400ms (remote/blackhole failures). (3) While down,
the socket is redialed every 2s — when the WAN returns, a fresh NAT
binding is made and the path re-registers (HELLO) and re-earns UP status
(3 probe acks) and its traffic share (loss factor ramp). Sessions survive
because the inner tunnel IPs never change.

**The reorder hold tunes itself.** Each receiver measures per-path one-way
delay (sender timestamps against its own clock — offsets cancel across
paths because the sender clock is shared) and sets the gap timeout to
`(max−min) + 2·jitter`, clamped to [2ms, 100ms]. Late stragglers are
*passed through* rather than dropped: the payload is WG ciphertext, so the
anti-replay window sorts it out.

**FEC repairs what striping cannot hide.** Bulk packets are grouped k at
a time (8ms flush); m Reed-Solomon parity shards ride as separate
datagrams. The receiver rebuilds any lost packet from k of k+m shards and
re-injects it into the reorder buffer — arriving well before the inner
TCP would retransmit. The (k,m) geometry follows the traffic-weighted
loss EWMA: off below 0.1% loss, up to 5:2 above 5%. REALTIME does not use
FEC: duplication has zero added latency.

## Security model

- Data plane: WireGuard end-to-end (Noise, ChaCha20-Poly1305). The Treccia
  framing around it is *not* encrypted; an on-path observer sees sequence
  numbers and class bits (comparable metadata exposure to plain WireGuard
  packet sizes/timing).
- Control plane (HELLO/PROBE/CTRL/BYE): keyed BLAKE2s-128 tag over the
  whole datagram with a shared PSK, 30s replay window on authenticated
  timestamps.
- Residual risk, by design: DATA/FEC datagrams are not individually
  authenticated at the tunnel layer (the payload is WG-authenticated
  anyway). Someone who learns the 32-bit session id could inject datagrams
  that occupy reorder slots. Mitigations: ids are random, off-path
  guessing is rate-limited by the window, and the buffer resets cleanly;
  per-packet SipHash negotiated in HELLO is the planned v2 hardening.

## Repo map

| Package | Role |
|---|---|
| `internal/wire` | datagram formats, control-plane MAC |
| `internal/wgbridge` | wireguard-go embedding: TUN shim, engine bind, correlator, keys |
| `internal/engine` | client/server datapaths, session handling, metrics |
| `internal/pathmon` | per-path estimator (RTT/loss/capacity), OWD stats, probes state |
| `internal/sched` | smooth deficit-WRR |
| `internal/reorder` | resequencing ring with adaptive hold |
| `internal/fec` | Reed-Solomon encoder/decoder + adaptive controller |
| `internal/classify` | 5-tuple flow table, heuristics, rule overrides |
| `internal/dashboard` | embedded live metrics page (SSE) |
| `test/netns` | reproducible multi-WAN rig (namespaces + tc) and e2e suites |
