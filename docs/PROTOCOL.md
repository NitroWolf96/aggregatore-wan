# Treccia wire protocol v1

All multi-byte fields are big-endian. Every datagram starts with a 4-byte
common header; the protocol version lives in the high nibble of byte 0 and
a major mismatch is rejected at HELLO time.

```
offset  size  field
0       1     version(4 bits) | type(4 bits)
1       1     flags
2       1     path_id
3       1     reserved/epoch
```

Types: `0 DATA · 1 PROBE · 2 PROBE_ACK · 3 CTRL · 4 FEC · 5 HELLO ·
6 HELLO_ACK · 7 BYE`

Flags: `b0 DUP` (redundant copy of an already-sent packet) ·
`b1 FEC_INFO` (DATA carries FEC group fields) · `b2-b3 class`
(`0 bulk · 1 realtime · 2 interactive`)

## DATA (type 0)

```
4   4  session_id    random per client run, identifies the session behind CGNAT
8   4  global_seq    bulk: ordered stream consumed by the reorder buffer
                     realtime/interactive: separate free-running space
12  4  path_seq      per-path monotonic counter -> per-link loss measurement
16  4  tx_ts         sender monotonic clock, µs mod 2^32 -> relative OWD
[20 3  fec_group ]   only when FEC_INFO is set
[23 1  fec_index ]
20|24  ...           payload = WireGuard ciphertext
```

Worst-case overhead per packet: 20 (IP) + 8 (UDP) + 24 (Treccia) + 32 (WG)
= **84 bytes**, hence the default tunnel MTU of **1344** (= 1428 − 84,
safe behind typical 4G APNs; a multiple of 16, so full-size packets take
no WireGuard padding).

## FEC (type 4) — data plane, unauthenticated like DATA

```
4   4  session_id
8   3  group         24-bit rolling group id
11  1  index         in [k, k+m) for parity shards
12  1  k             data shards in the group (receivers learn it here)
13  1  m             parity shards
14  2  shard_len
16  ...shard         [global_seq(4) | ct_len(2) | ciphertext] zero-padded
```

Shards are self-describing, so a reconstructed shard yields the sequence
number and exact ciphertext of the lost packet. DATA packets only carry
`group`+`index` (4 bytes); one parity arrival reveals the geometry.

## Control plane — authenticated

Every control datagram ends with a **keyed BLAKE2s-128 tag (16 bytes)**
over the entire datagram, header included (so `path_id` is authenticated).
Key = `BLAKE2s-256("treccia-control-v1:" + control_psk)`. Timestamps are
accepted within ±30s.

### HELLO (5) / HELLO_ACK (6) — 44 bytes

```
4   4  session_id
8   8  client_id      random identity; guards against session-id collisions
16  4  feature_bits   0 for v1
20  8  unix_ts
28  16 MAC
```

A HELLO registers `(session, path_id) → source address` at the server; the
ACK echoes the fields with the server's timestamp. Clients re-HELLO every
1s until acked, then every 15s, and immediately after redialing a socket
(fresh NAT binding).

### PROBE (1) — 36 bytes / PROBE_ACK (2) — 48 bytes

```
PROBE:      session(4) probe_seq(4) tx_ts_us(8, full width) MAC(16)
PROBE_ACK:  session(4) probe_seq(4) tx_ts_us(8) hold_us(4) MAC(16)
```

Both sides probe every path at 100ms (500ms while down). RTT =
`now − tx_ts − hold`. Three unanswered probes → DOWN; three consecutive
acks → UP. Probes double as NAT keepalives.

### CTRL (3) — receiver feedback, TLV

Sent by each receiver every 50ms under traffic (250ms idle) on its
best path: `session(4)` + TLV records + MAC. Record type 1, PATH_STATS
(25 bytes payload):

```
path_id(1) highest_path_seq(4) rx_pkts(4) rx_bytes(8)
owd_min_us(4) owd_avg_us(4)
```

From consecutive reports the sender derives per-path loss
(`Δexpected − Δreceived`), delivery rate (`Δbytes/Δt`, fed to the
windowed-max capacity estimator) and the scheduler weights. Unknown TLV
types are skipped, so future records (SACK bitmaps, FEC stats) are
backward-compatible.

### BYE (7) — 32 bytes

```
session(4) unix_ts(8) MAC(16)
```

Cleanly removes one path; the last path removes the session.

## Connection lifecycle

1. Client picks a random `session_id`/`client_id`, opens one UDP socket
   per WAN (bound to that WAN's source address) toward the single server
   port, and HELLOs on each.
2. WireGuard handshakes ride the registered paths as INTERACTIVE.
3. Probes bring paths UP; CTRL feedback starts driving weights; data flows.
4. Any valid datagram updates the server's `(session, path) → address`
   mapping — per-path roaming, CGNAT-safe because everything is
   client-initiated.
5. Silence expires paths (45s) and sessions (5min); BYE shortcuts both.
