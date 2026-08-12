package engine

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
	"github.com/nitrowolf96/aggregatore-wan/internal/control"
	"github.com/nitrowolf96/aggregatore-wan/internal/fec"
	"github.com/nitrowolf96/aggregatore-wan/internal/pathmon"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Path is one WAN uplink: a UDP socket bound to that WAN's source address
// and connected to the aggregation server, plus its quality estimators.
type Path struct {
	ID   uint8
	Name string

	bindIP     string
	serverAddr string

	connMu sync.RWMutex
	conn   *net.UDPConn
	closed bool // guarded by connMu; dial refuses to resurrect a closed path

	pathSeq    atomic.Uint32
	registered atomic.Bool
	lastRxNano atomic.Int64
	lastHello  atomic.Int64
	lastRedial atomic.Int64

	Link *pathmon.Link
	Rx   *pathmon.RxStats
}

func (p *Path) getConn() *net.UDPConn {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	return p.conn
}

// write sends one datagram on the current socket.
func (p *Path) write(b []byte) error {
	c := p.getConn()
	if c == nil {
		return net.ErrClosed
	}
	_, err := c.Write(b)
	return err
}

// dial (re)creates the socket; the bind address may have come and gone with
// the WAN interface.
func (p *Path) dial() error {
	raddr, err := net.ResolveUDPAddr("udp", p.serverAddr)
	if err != nil {
		return err
	}
	var laddr *net.UDPAddr
	if p.bindIP != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(p.bindIP)}
		if laddr.IP == nil {
			return fmt.Errorf("invalid bind address %q", p.bindIP)
		}
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	p.connMu.Lock()
	if p.closed {
		p.connMu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	old := p.conn
	p.conn = conn
	p.connMu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// close shuts the path's socket down for good.
func (p *Path) close() {
	p.connMu.Lock()
	p.closed = true
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.connMu.Unlock()
}

// Control-plane cadence.
const (
	helloRetry   = 1 * time.Second
	helloRefresh = 15 * time.Second
	ctrlBusy     = 50 * time.Millisecond
	ctrlIdle     = 250 * time.Millisecond
	holdRetune   = 1 * time.Second
	redialEvery  = 2 * time.Second
)

// AddPath creates the WAN socket for one uplink. bindIP may be empty (any
// source; useful in tests), otherwise it must be an address on the WAN's
// interface so policy routing steers the socket out of that WAN.
func (e *Engine) AddPath(name, bindIP, serverAddr string) (*Path, error) {
	e.pathsMu.Lock()
	id := uint8(len(e.paths))
	p := &Path{
		ID: id, Name: name,
		bindIP: bindIP, serverAddr: serverAddr,
		Link: pathmon.NewLink(), Rx: &pathmon.RxStats{},
	}
	p.lastRedial.Store(time.Now().UnixNano())
	e.paths = append(e.paths, p)
	e.pathsMu.Unlock()

	if err := p.dial(); err != nil {
		return nil, fmt.Errorf("path %s: %w", name, err)
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.clientRxLoop(p)
	}()
	e.log.Info("path added", "path", name, "id", id, "bind", bindIP, "server", serverAddr)
	return p, nil
}

// Run drives the control plane loops until the engine is closed. On the
// server everything is started by Listen, so Run is a no-op there.
func (e *Engine) Run() {
	if e.mode != ModeClient {
		return
	}
	loops := []func(){e.helloLoop, e.clientProbeLoop, e.clientCtrlLoop}
	if e.fecEnc != nil {
		loops = append(loops, e.fecFlushLoop)
	}
	for _, loop := range loops {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			loop()
		}()
	}
}

// fecFlushLoop closes stale partial FEC groups so parity is never held
// back on a quiet stream.
func (e *Engine) fecFlushLoop() {
	t := time.NewTicker(fec.FlushTimeout / 2)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-t.C:
			e.fecEnc.Flush(now)
		}
	}
}

// WaitReady blocks until at least one path is registered or the timeout
// expires.
func (e *Engine) WaitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.activePath() != nil {
			return nil
		}
		select {
		case <-e.ctx.Done():
			return e.ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return errors.New("engine: no path registered before timeout")
}

// activePath returns any registered path (used for readiness checks).
func (e *Engine) activePath() *Path {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for _, p := range e.paths {
		if p.registered.Load() {
			return p
		}
	}
	return nil
}

func (e *Engine) allPaths() []*Path {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return append([]*Path(nil), e.paths...)
}

// sendablePaths returns the paths eligible for data. Preferably registered
// AND probed-up; before the first probes complete (or if probing broke) it
// falls back to merely registered paths so the tunnel still bootstraps.
func (e *Engine) sendablePaths() []*Path {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	up := make([]*Path, 0, len(e.paths))
	registered := make([]*Path, 0, len(e.paths))
	for _, p := range e.paths {
		if !p.registered.Load() {
			continue
		}
		registered = append(registered, p)
		if p.Link.Up() {
			up = append(up, p)
		}
	}
	if len(up) > 0 {
		return up
	}
	return registered
}

// clientSend is the wgbridge SendFunc: WireGuard ciphertext leaves here.
// BULK is striped in proportion to each path's measured capacity;
// REALTIME is duplicated on the two lowest-latency paths (the second copy
// is deduplicated for free by WireGuard's anti-replay window); INTERACTIVE
// sticks to the single best-latency path.
func (e *Engine) clientSend(bufs [][]byte, _ *wgbridge.SessionEndpoint) error {
	for _, ct := range bufs {
		paths := e.sendablePaths()
		if len(paths) == 0 {
			e.holdPending(ct)
			continue
		}
		class := e.classifyCt(ct)

		if len(paths) == 1 && class != wire.ClassBulk {
			e.sendDataOn(paths[0], class, false, e.session, e.rtSeq.Add(1), fecTag{}, ct)
			continue
		}

		switch class {
		case wire.ClassRealtime, wire.ClassInteractive:
			snaps := make([]pathmon.Snapshot, len(paths))
			for i, p := range paths {
				snaps[i] = p.Link.Snapshot()
			}
			first, second := pathmon.BestPair(snaps)
			if first < 0 {
				break // no probed path yet: fall through to weighted striping
			}
			seq := e.rtSeq.Add(1)
			e.sendDataOn(paths[first], class, false, e.session, seq, fecTag{}, ct)
			if class == wire.ClassRealtime && second >= 0 {
				e.sendDataOn(paths[second], class, true, e.session, seq, fecTag{}, ct)
			}
			continue
		}

		var p *Path
		if len(paths) == 1 {
			p = paths[0]
		} else {
			ids := make([]uint8, len(paths))
			weights := make([]float64, len(paths))
			for i, pp := range paths {
				ids[i] = pp.ID
				weights[i] = pp.Link.Weight()
			}
			p = paths[e.wsched.Pick(ids, weights)]
		}
		seq := e.globalSeq.Add(1)
		var tag fecTag
		if e.fecEnc != nil {
			if g, idx, on := e.fecEnc.Add(seq, ct, time.Now()); on {
				tag = fecTag{on: true, group: g, index: idx}
			}
		}
		e.sendDataOn(p, wire.ClassBulk, false, e.session, seq, tag, ct)
	}
	return nil
}

// clientEmitParity schedules one parity shard onto the weighted paths.
func (e *Engine) clientEmitParity(group uint32, index, k, m uint8, shard []byte) {
	paths := e.sendablePaths()
	if len(paths) == 0 {
		return
	}
	p := paths[0]
	if len(paths) > 1 {
		ids := make([]uint8, len(paths))
		weights := make([]float64, len(paths))
		for i, pp := range paths {
			ids[i] = pp.ID
			weights[i] = pp.Link.Weight()
		}
		p = paths[e.wsched.Pick(ids, weights)]
	}
	slab := buffers.Get()
	defer buffers.Put(slab)
	f := wire.FECHeader{
		Header:   wire.Header{PathID: p.ID},
		Session:  e.session,
		Group:    group,
		Index:    index,
		K:        k,
		M:        m,
		ShardLen: uint16(len(shard)),
	}
	n := wire.PutFECHeader(*slab, &f)
	if n+len(shard) > len(*slab) {
		return
	}
	c := copy((*slab)[n:], shard)
	if err := p.write((*slab)[:n+c]); err == nil {
		e.Stats.TxPackets.Add(1)
		e.Stats.TxBytes.Add(uint64(n + c))
	}
}

// sendDataOn frames one ciphertext datagram and writes it to the path.
func (e *Engine) sendDataOn(p *Path, class uint8, dup bool, session, seq uint32, tag fecTag, ct []byte) {
	slab := buffers.Get()
	defer buffers.Put(slab)
	flags := wire.ClassFlags(class)
	if dup {
		flags |= wire.FlagDup
	}
	if tag.on {
		flags |= wire.FlagFECInfo
	}
	d := wire.DataHeader{
		Header:    wire.Header{Type: wire.TypeData, Flags: flags, PathID: p.ID},
		Session:   session,
		GlobalSeq: seq,
		PathSeq:   p.pathSeq.Add(1),
		TxTS:      e.txTS(),
		FECGroup:  tag.group,
		FECIndex:  tag.index,
	}
	n := wire.PutDataHeader(*slab, &d)
	if n+len(ct) > len(*slab) {
		e.Stats.RxDropMalformed.Add(1)
		return
	}
	m := copy((*slab)[n:], ct)
	if err := p.write((*slab)[:n+m]); err != nil {
		p.Link.MarkDown()
		return
	}
	e.Stats.TxPackets.Add(1)
	e.Stats.TxBytes.Add(uint64(n + m))
}

func (e *Engine) clientRxLoop(p *Path) {
	for {
		conn := p.getConn()
		if conn == nil {
			return
		}
		slab := buffers.Get()
		n, err := conn.Read(*slab)
		if err != nil {
			buffers.Put(slab)
			if e.ctx.Err() != nil {
				return
			}
			if p.getConn() != conn {
				continue // socket was replaced by a redial
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		e.handleClientDatagram(p, slab, n)
	}
}

func (e *Engine) handleClientDatagram(p *Path, slab *[]byte, n int) {
	dgram := (*slab)[:n]
	h, err := wire.ParseHeader(dgram)
	if err != nil {
		e.Stats.RxDropMalformed.Add(1)
		buffers.Put(slab)
		return
	}
	now := time.Now()
	switch h.Type {
	case wire.TypeData:
		d, payload, err := wire.ParseDataHeader(dgram)
		if err != nil || d.Session != e.session {
			e.Stats.RxDropMalformed.Add(1)
			buffers.Put(slab)
			return
		}
		p.lastRxNano.Store(now.UnixNano())
		p.Rx.OnData(d.PathSeq, n, int32(e.txTS()-d.TxTS), now)
		e.Stats.RxPackets.Add(1)
		e.Stats.RxBytes.Add(uint64(n))
		pkt := buffers.Packet{Slab: slab, Off: d.Len(), Len: len(payload)}
		if d.Class() == wire.ClassBulk {
			if d.Flags&wire.FlagFECInfo != 0 && e.fecDec != nil {
				// The decoder copies the shard before Push may recycle the slab.
				e.fecDec.AddData(d.FECGroup, d.FECIndex, d.GlobalSeq, payload, now)
			}
			e.reorderBuf.Push(d.GlobalSeq, pkt)
		} else if !e.bind.Deliver(pkt, e.clientEp) {
			// Latency-sensitive classes bypass the reorder buffer; WireGuard
			// anti-replay swallows the duplicated copies.
			e.Stats.RxDropQueue.Add(1)
		}
		return
	case wire.TypeFEC:
		if f, shard, err := wire.ParseFEC(dgram); err == nil && f.Session == e.session && e.fecDec != nil {
			p.lastRxNano.Store(now.UnixNano())
			e.Stats.RxPackets.Add(1)
			e.Stats.RxBytes.Add(uint64(n))
			e.fecDec.AddParity(f.Group, f.Index, f.K, f.M, shard, now)
		}
	case wire.TypeProbe:
		if hh, pr, ok := control.ParseProbe(dgram, e.mac); ok && pr.Session == e.session {
			ack := control.EncodeProbeAck(wire.Header{PathID: hh.PathID},
				control.ProbeAck{Session: pr.Session, Seq: pr.Seq, TxTS: pr.TxTS}, e.mac)
			p.write(ack)
		}
	case wire.TypeProbeAck:
		if hh, ack, ok := control.ParseProbeAck(dgram, e.mac); ok && ack.Session == e.session && hh.PathID == p.ID {
			rtt := time.Duration(e.nowUS()-ack.TxTS)*time.Microsecond - time.Duration(ack.HoldUS)*time.Microsecond
			if p.Link.OnProbeAck(ack.Seq, rtt) {
				e.log.Info("path up", "path", p.Name, "srtt", rtt)
			}
			p.lastRxNano.Store(now.UnixNano())
		}
	case wire.TypeCtrl:
		if _, c, ok := control.ParseCtrl(dgram, e.mac); ok && c.Session == e.session {
			e.onClientCtrl(c, now)
		}
	case wire.TypeHelloAck:
		if hh, m, ok := control.ParseHello(dgram, e.mac); ok &&
			hh.PathID == p.ID && m.Session == e.session && m.ClientID == e.clientID &&
			control.FreshTS(m.UnixTS, now) {
			if !p.registered.Swap(true) {
				e.log.Info("path registered", "path", p.Name, "id", p.ID)
				e.flushPending()
			}
			p.lastRxNano.Store(now.UnixNano())
		}
	}
	buffers.Put(slab)
}

// pendingCap bounds the pre-registration queue; a cold start only ever
// stages a handful of handshake/keepalive datagrams.
const pendingCap = 64

// holdPending stages ciphertext until a path registers.
func (e *Engine) holdPending(ct []byte) {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	if len(e.pending) >= pendingCap {
		e.Stats.TxDropNoPath.Add(1)
		return
	}
	e.pending = append(e.pending, append([]byte(nil), ct...))
}

// flushPending replays staged ciphertext through the normal send path once
// the first path has registered.
func (e *Engine) flushPending() {
	e.pendingMu.Lock()
	staged := e.pending
	e.pending = nil
	e.pendingMu.Unlock()
	if len(staged) == 0 {
		return
	}
	e.log.Debug("flushing pre-registration ciphertext", "packets", len(staged))
	e.clientSend(staged, nil)
}

// onClientCtrl feeds the server's receive report into each path estimator.
func (e *Engine) onClientCtrl(c control.Ctrl, now time.Time) {
	paths := e.allPaths()
	for _, ps := range c.Paths {
		if int(ps.PathID) < len(paths) {
			paths[ps.PathID].Link.OnCtrl(ps.Highest, ps.RxPkts, ps.RxBytes, now)
		}
	}
}

func (e *Engine) helloLoop() {
	t := time.NewTicker(helloRetry)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		for _, p := range e.allPaths() {
			refresh := helloRefresh
			if !p.registered.Load() {
				refresh = helloRetry
			}
			if now.UnixNano()-p.lastHello.Load() < refresh.Nanoseconds() {
				continue
			}
			p.lastHello.Store(now.UnixNano())
			dgram := control.EncodeHello(
				wire.Header{PathID: p.ID},
				control.Hello{Session: e.session, ClientID: e.clientID, UnixTS: now.Unix()},
				e.mac, false)
			p.write(dgram)
		}
	}
}

// clientProbeLoop probes every path at 100ms (500ms while down), detects
// dead paths and redials sockets whose WAN came back.
func (e *Engine) clientProbeLoop() {
	t := time.NewTicker(pathmon.ProbeInterval)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		tick++
		now := time.Now()
		for _, p := range e.allPaths() {
			if !p.registered.Load() {
				// Waiting for a HELLO ack; if the WAN address came back a
				// fresh socket (and NAT binding) may be needed.
				if now.UnixNano()-p.lastRedial.Load() > redialEvery.Nanoseconds() {
					p.lastRedial.Store(now.UnixNano())
					p.dial() // best effort
				}
				continue
			}
			if !p.Link.Up() && tick%5 != 0 {
				continue // 500ms cadence while down
			}
			seq, wentDown := p.Link.OnProbeSent()
			if wentDown {
				e.log.Warn("path down", "path", p.Name)
			}
			probe := control.EncodeProbe(wire.Header{PathID: p.ID},
				control.Probe{Session: e.session, Seq: seq, TxTS: e.nowUS()}, e.mac)
			if err := p.write(probe); err != nil {
				p.Link.MarkDown()
				if now.UnixNano()-p.lastRedial.Load() > redialEvery.Nanoseconds() {
					p.lastRedial.Store(now.UnixNano())
					if p.dial() == nil {
						// Fresh socket means a fresh NAT binding: re-register.
						p.registered.Store(false)
						p.lastHello.Store(0)
					}
				}
			}
		}
	}
}

// clientCtrlLoop reports this side's receive stats to the server and
// retunes the reorder hold from the measured delay spread.
func (e *Engine) clientCtrlLoop() {
	t := time.NewTicker(ctrlBusy)
	defer t.Stop()
	var lastSent time.Time
	var lastRxPkts uint64
	var lastRetune time.Time
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		rx := e.Stats.RxPackets.Load()
		busy := rx != lastRxPkts
		if !busy && now.Sub(lastSent) < ctrlIdle {
			continue
		}
		lastRxPkts = rx

		paths := e.allPaths()
		c := control.Ctrl{Session: e.session}
		for _, p := range paths {
			if highest, pkts, bytes, owdMin, owdAvg, ok := p.Rx.Report(); ok {
				c.Paths = append(c.Paths, control.PathStats{
					PathID: p.ID, Highest: highest, RxPkts: pkts, RxBytes: bytes,
					OwdMinUS: owdMin, OwdAvgUS: owdAvg,
				})
			}
		}
		if len(c.Paths) == 0 {
			continue
		}
		best := bestCtrlPath(paths)
		if best == nil {
			continue
		}
		best.write(control.EncodeCtrl(wire.Header{PathID: best.ID}, c, e.mac))
		lastSent = now

		if now.Sub(lastRetune) >= holdRetune {
			lastRetune = now
			views := make([][2]float64, 0, len(paths))
			snaps := make([]pathmon.Snapshot, 0, len(paths))
			for _, p := range paths {
				if e, j, ok := p.Rx.OwdView(now, 3*time.Second); ok {
					views = append(views, [2]float64{e, j})
				}
				snaps = append(snaps, p.Link.Snapshot())
			}
			if hold := pathmon.ComputeHold(views); hold > 0 {
				e.reorderBuf.SetHold(hold)
			}
			e.retuneFEC(e.fecEnc, snaps)
		}
	}
}

// bestCtrlPath prefers the lowest-SRTT up path for feedback delivery.
func bestCtrlPath(paths []*Path) *Path {
	var best *Path
	var bestSRTT time.Duration
	for _, p := range paths {
		if !p.registered.Load() {
			continue
		}
		s := p.Link.Snapshot()
		if !s.Up {
			continue
		}
		if best == nil || (s.SRTT > 0 && s.SRTT < bestSRTT) {
			best, bestSRTT = p, s.SRTT
		}
	}
	if best != nil {
		return best
	}
	for _, p := range paths {
		if p.registered.Load() {
			return p
		}
	}
	return nil
}

func (e *Engine) sendByes() {
	now := time.Now().Unix()
	for _, p := range e.allPaths() {
		if p.registered.Load() {
			dgram := control.EncodeBye(wire.Header{PathID: p.ID}, control.Bye{Session: e.session, UnixTS: now}, e.mac)
			p.write(dgram)
		}
	}
}
