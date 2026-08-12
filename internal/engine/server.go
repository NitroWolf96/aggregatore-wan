package engine

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
	"github.com/nitrowolf96/aggregatore-wan/internal/control"
	"github.com/nitrowolf96/aggregatore-wan/internal/fec"
	"github.com/nitrowolf96/aggregatore-wan/internal/pathmon"
	"github.com/nitrowolf96/aggregatore-wan/internal/reorder"
	"github.com/nitrowolf96/aggregatore-wan/internal/sched"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// sessionTimeout removes sessions that have been completely silent.
const sessionTimeout = 5 * time.Minute

// pathStaleAfter excludes paths from return traffic when nothing has
// arrived on them recently (probes keep live paths warm at 100ms).
const pathStaleAfter = 45 * time.Second

type serverState struct {
	sock     *net.UDPConn
	mu       sync.RWMutex
	sessions map[uint32]*Session
}

func newServerState() *serverState {
	return &serverState{sessions: make(map[uint32]*Session)}
}

// pathState is the server-side view of one client path.
type pathState struct {
	id     uint8
	addr   netip.AddrPort
	lastRx int64 // unix nanos of the last inbound datagram on this path

	Link *pathmon.Link
	Rx   *pathmon.RxStats
}

// Session is the server-side view of one client and its registered paths.
type Session struct {
	ID       uint32
	ClientID uint64
	Ep       *wgbridge.SessionEndpoint

	mu        sync.RWMutex
	paths     map[uint8]*pathState
	lastSeen  atomic.Int64
	globalSeq atomic.Uint32
	rtSeq     atomic.Uint32
	pathSeq   [256]atomic.Uint32
	reorder   *reorder.Buffer[buffers.Packet]
	wsched    *sched.Weighted
	fecEnc    *fec.Encoder
	fecDec    *fec.Decoder
}

// touchPath refreshes (or creates) the state of one path; the newest source
// address wins (per-path roaming, like WireGuard).
func (s *Session) touchPath(pathID uint8, addr netip.AddrPort, now int64) *pathState {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.paths[pathID]
	if ps == nil {
		ps = &pathState{id: pathID, Link: pathmon.NewLink(), Rx: &pathmon.RxStats{}}
		s.paths[pathID] = ps
	}
	ps.addr = addr
	ps.lastRx = now
	return ps
}

func (s *Session) path(pathID uint8) *pathState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.paths[pathID]
}

// alivePaths snapshots the recently active paths.
func (s *Session) alivePaths(now int64) []*pathState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*pathState, 0, len(s.paths))
	cutoff := now - pathStaleAfter.Nanoseconds()
	for _, ps := range s.paths {
		if ps.lastRx >= cutoff {
			out = append(out, ps)
		}
	}
	return out
}

// Listen opens the single aggregation socket and starts the server loops.
func (e *Engine) Listen(listen string) error {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("listen address %s: %w", listen, err)
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	e.server.sock = sock
	loops := []func(){e.serverRxLoop, e.serverControlLoop, e.sessionReaper}
	if !e.fecDisabled {
		loops = append(loops, e.serverFecFlushLoop)
	}
	for _, loop := range loops {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			loop()
		}()
	}
	e.log.Info("listening", "addr", sock.LocalAddr())
	return nil
}

// serverFecFlushLoop closes stale partial FEC groups of every session.
func (e *Engine) serverFecFlushLoop() {
	t := time.NewTicker(fec.FlushTimeout / 2)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-t.C:
			for _, sess := range e.allSessions() {
				if sess.fecEnc != nil {
					sess.fecEnc.Flush(now)
				}
			}
		}
	}
}

func (e *Engine) serverRxLoop() {
	for {
		slab := buffers.Get()
		n, src, err := e.server.sock.ReadFromUDPAddrPort(*slab)
		if err != nil {
			buffers.Put(slab)
			if e.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		e.handleServerDatagram(slab, n, src)
	}
}

func (e *Engine) handleServerDatagram(slab *[]byte, n int, src netip.AddrPort) {
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
		if err != nil {
			e.Stats.RxDropMalformed.Add(1)
			buffers.Put(slab)
			return
		}
		sess := e.lookupSession(d.Session)
		if sess == nil {
			e.Stats.RxDropUnknown.Add(1)
			buffers.Put(slab)
			return
		}
		ps := sess.touchPath(d.PathID, src, now.UnixNano())
		ps.Rx.OnData(d.PathSeq, n, int32(e.txTS()-d.TxTS), now)
		sess.lastSeen.Store(now.UnixNano())
		e.Stats.RxPackets.Add(1)
		e.Stats.RxBytes.Add(uint64(n))
		pkt := buffers.Packet{Slab: slab, Off: d.Len(), Len: len(payload)}
		if d.Class() == wire.ClassBulk {
			if d.Flags&wire.FlagFECInfo != 0 && sess.fecDec != nil {
				sess.fecDec.AddData(d.FECGroup, d.FECIndex, d.GlobalSeq, payload, now)
			}
			sess.reorder.Push(d.GlobalSeq, pkt)
		} else if !e.bind.Deliver(pkt, sess.Ep) {
			e.Stats.RxDropQueue.Add(1)
		}
		return
	case wire.TypeFEC:
		if f, shard, err := wire.ParseFEC(dgram); err == nil {
			if sess := e.lookupSession(f.Session); sess != nil && sess.fecDec != nil {
				e.Stats.RxPackets.Add(1)
				e.Stats.RxBytes.Add(uint64(n))
				sess.fecDec.AddParity(f.Group, f.Index, f.K, f.M, shard, now)
			}
		}
	case wire.TypeProbe:
		if hh, pr, ok := control.ParseProbe(dgram, e.mac); ok {
			if sess := e.lookupSession(pr.Session); sess != nil {
				sess.touchPath(hh.PathID, src, now.UnixNano())
				ack := control.EncodeProbeAck(wire.Header{PathID: hh.PathID},
					control.ProbeAck{Session: pr.Session, Seq: pr.Seq, TxTS: pr.TxTS}, e.mac)
				e.server.sock.WriteToUDPAddrPort(ack, src)
			}
		}
	case wire.TypeProbeAck:
		if hh, ack, ok := control.ParseProbeAck(dgram, e.mac); ok {
			if sess := e.lookupSession(ack.Session); sess != nil {
				if ps := sess.path(hh.PathID); ps != nil {
					rtt := time.Duration(e.nowUS()-ack.TxTS)*time.Microsecond - time.Duration(ack.HoldUS)*time.Microsecond
					if ps.Link.OnProbeAck(ack.Seq, rtt) {
						e.log.Info("path up", "session", sess.ID, "path", hh.PathID, "srtt", rtt)
					}
				}
			}
		}
	case wire.TypeCtrl:
		if _, c, ok := control.ParseCtrl(dgram, e.mac); ok {
			if sess := e.lookupSession(c.Session); sess != nil {
				for _, st := range c.Paths {
					if ps := sess.path(st.PathID); ps != nil {
						ps.Link.OnCtrl(st.Highest, st.RxPkts, st.RxBytes, int32(st.OwdMinUS), int32(st.OwdAvgUS), now)
					}
				}
			}
		}
	case wire.TypeHello:
		e.handleHello(dgram, src)
	case wire.TypeBye:
		if hb, m, ok := control.ParseBye(dgram, e.mac); ok && control.FreshTS(m.UnixTS, now) {
			e.removeSessionPath(m.Session, hb.PathID)
		}
	}
	buffers.Put(slab)
}

func (e *Engine) handleHello(dgram []byte, src netip.AddrPort) {
	hh, m, ok := control.ParseHello(dgram, e.mac)
	if !ok || hh.Type != wire.TypeHello || !control.FreshTS(m.UnixTS, time.Now()) {
		e.Stats.RxDropMalformed.Add(1)
		return
	}
	st := e.server
	st.mu.Lock()
	sess := st.sessions[m.Session]
	if sess == nil {
		ep := &wgbridge.SessionEndpoint{Session: m.Session}
		sess = &Session{
			ID:       m.Session,
			ClientID: m.ClientID,
			Ep:       ep,
			paths:    make(map[uint8]*pathState),
			reorder:  e.newReorder(ep),
			wsched:   sched.NewWeighted(),
		}
		if !e.fecDisabled {
			s := sess
			s.fecEnc = fec.NewEncoder(func(group uint32, index, k, m uint8, shard []byte) {
				e.serverEmitParity(s, group, index, k, m, shard)
			})
			s.fecEnc.SetParams(e.fecForce)
			s.fecDec = fec.NewDecoder(func(seq uint32, ct []byte) {
				slab := buffers.Get()
				n := copy(*slab, ct)
				s.reorder.Push(seq, buffers.Packet{Slab: slab, Len: n})
			})
		}
		st.sessions[m.Session] = sess
		e.log.Info("session created", "session", m.Session, "src", src)
	}
	st.mu.Unlock()
	if sess.ClientID != m.ClientID {
		// Session id collision between different clients: ignore the newcomer.
		e.Stats.RxDropUnknown.Add(1)
		return
	}
	now := time.Now().UnixNano()
	sess.touchPath(hh.PathID, src, now)
	sess.lastSeen.Store(now)

	ack := control.EncodeHello(
		wire.Header{PathID: hh.PathID},
		control.Hello{Session: m.Session, ClientID: m.ClientID, UnixTS: time.Now().Unix()},
		e.mac, true)
	e.server.sock.WriteToUDPAddrPort(ack, src)
}

func (e *Engine) lookupSession(id uint32) *Session {
	e.server.mu.RLock()
	s := e.server.sessions[id]
	e.server.mu.RUnlock()
	return s
}

func (e *Engine) allSessions() []*Session {
	e.server.mu.RLock()
	defer e.server.mu.RUnlock()
	out := make([]*Session, 0, len(e.server.sessions))
	for _, s := range e.server.sessions {
		out = append(out, s)
	}
	return out
}

func (e *Engine) removeSessionPath(sessionID uint32, pathID uint8) {
	sess := e.lookupSession(sessionID)
	if sess == nil {
		return
	}
	sess.mu.Lock()
	delete(sess.paths, pathID)
	empty := len(sess.paths) == 0
	sess.mu.Unlock()
	if empty {
		e.server.mu.Lock()
		delete(e.server.sessions, sessionID)
		e.server.mu.Unlock()
		sess.reorder.Close()
		e.log.Info("session removed", "session", sessionID)
	}
}

func (e *Engine) sessionReaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		cutoff := time.Now().Add(-sessionTimeout).UnixNano()
		e.server.mu.Lock()
		for id, s := range e.server.sessions {
			if s.lastSeen.Load() < cutoff {
				delete(e.server.sessions, id)
				s.reorder.Close()
				e.log.Info("session expired", "session", id)
			}
		}
		e.server.mu.Unlock()
	}
}

// serverControlLoop probes every alive path of every session (100ms, 500ms
// while down) and reports the server's receive stats back to each client.
func (e *Engine) serverControlLoop() {
	t := time.NewTicker(ctrlBusy) // 50ms base tick
	defer t.Stop()
	tick := 0
	lastRx := make(map[uint32]uint32)
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		tick++
		now := time.Now()
		for _, sess := range e.allSessions() {
			alive := sess.alivePaths(now.UnixNano())
			if len(alive) == 0 {
				continue
			}
			if tick%2 == 0 { // probes at 100ms
				for _, ps := range alive {
					if !ps.Link.Up() && tick%10 != 0 {
						continue // 500ms cadence while down
					}
					seq, wentDown := ps.Link.OnProbeSent(now)
					if wentDown {
						e.log.Warn("path down", "session", sess.ID, "path", ps.id)
					}
					probe := control.EncodeProbe(wire.Header{PathID: ps.id},
						control.Probe{Session: sess.ID, Seq: seq, TxTS: e.nowUS()}, e.mac)
					e.server.sock.WriteToUDPAddrPort(probe, ps.addr)
				}
			}

			// CTRL: 50ms under traffic, 250ms idle.
			c := control.Ctrl{Session: sess.ID}
			for _, ps := range alive {
				if highest, pkts, bytes, owdMin, owdAvg, ok := ps.Rx.Report(); ok {
					c.Paths = append(c.Paths, control.PathStats{
						PathID: ps.id, Highest: highest, RxPkts: pkts, RxBytes: bytes,
						OwdMinUS: owdMin, OwdAvgUS: owdAvg,
					})
				}
			}
			if len(c.Paths) == 0 {
				continue
			}
			idleSkip := tick%5 != 0
			totalPkts := uint32(0)
			for _, p := range c.Paths {
				totalPkts += p.RxPkts
			}
			if totalPkts == lastRx[sess.ID] && idleSkip {
				continue
			}
			lastRx[sess.ID] = totalPkts
			best := bestServerCtrlPath(alive)
			if best == nil {
				continue
			}
			e.server.sock.WriteToUDPAddrPort(
				control.EncodeCtrl(wire.Header{PathID: best.id}, c, e.mac), best.addr)

			// Retune this session's reorder hold fast (250ms) and FEC 1/s.
			if tick%5 == 0 {
				views := make([][2]float64, 0, len(alive))
				for _, ps := range alive {
					if ew, j, ok := ps.Rx.OwdView(now, 3*time.Second); ok {
						views = append(views, [2]float64{ew, j})
					}
				}
				if hold := pathmon.ComputeHold(views); hold > 0 {
					sess.reorder.SetHold(hold)
				}
			}
			if tick%20 == 0 {
				snaps := make([]pathmon.Snapshot, 0, len(alive))
				for _, ps := range alive {
					snaps = append(snaps, ps.Link.Snapshot())
				}
				e.retuneFEC(sess.fecEnc, snaps)
			}
		}
	}
}

func bestServerCtrlPath(alive []*pathState) *pathState {
	var best *pathState
	var bestSRTT time.Duration
	for _, ps := range alive {
		s := ps.Link.Snapshot()
		if !s.Up {
			continue
		}
		if best == nil || (s.SRTT > 0 && s.SRTT < bestSRTT) {
			best, bestSRTT = ps, s.SRTT
		}
	}
	if best != nil {
		return best
	}
	var newest *pathState
	for _, ps := range alive {
		if newest == nil || ps.lastRx > newest.lastRx {
			newest = ps
		}
	}
	return newest
}

// serverSend is the wgbridge SendFunc of the server: return ciphertext is
// scheduled per packet across the client's alive paths.
func (e *Engine) serverSend(bufs [][]byte, ep *wgbridge.SessionEndpoint) error {
	sess := e.lookupSession(ep.Session)
	if sess == nil {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	for _, ct := range bufs {
		alive := sess.alivePaths(time.Now().UnixNano())
		usable := alive[:0:0]
		for _, ps := range alive {
			if ps.Link.Up() {
				usable = append(usable, ps)
			}
		}
		if len(usable) == 0 {
			usable = alive // bootstrap: probes not confirmed yet
		}
		if len(usable) == 0 {
			e.Stats.TxDropNoPath.Add(1)
			continue
		}
		class := e.classifyCt(ct)

		if len(usable) == 1 && class != wire.ClassBulk {
			e.serverSendData(sess, usable[0], class, false, sess.rtSeq.Add(1), fecTag{}, ct)
			continue
		}

		switch class {
		case wire.ClassRealtime, wire.ClassInteractive:
			snaps := make([]pathmon.Snapshot, len(usable))
			for i, u := range usable {
				snaps[i] = u.Link.Snapshot()
			}
			first, second := pathmon.BestPair(snaps)
			if first < 0 {
				break // fall through to weighted striping
			}
			seq := sess.rtSeq.Add(1)
			e.serverSendData(sess, usable[first], class, false, seq, fecTag{}, ct)
			if class == wire.ClassRealtime && second >= 0 {
				e.serverSendData(sess, usable[second], class, true, seq, fecTag{}, ct)
			}
			continue
		}

		ps := usable[0]
		if len(usable) > 1 {
			ids := make([]uint8, len(usable))
			weights := make([]float64, len(usable))
			for i, u := range usable {
				ids[i] = u.id
				weights[i] = u.Link.Weight()
			}
			ps = usable[sess.wsched.Pick(ids, weights)]
		}
		// Ingress AQM, as on the client: early-drop before sequencing.
		if prob := ps.Link.DropProb(); prob > 0 && rand.Float64() < prob {
			e.Stats.AQMDrops.Add(1)
			continue
		}
		seq := sess.globalSeq.Add(1)
		var tag fecTag
		if sess.fecEnc != nil {
			if g, idx, on := sess.fecEnc.Add(seq, ct, time.Now()); on {
				tag = fecTag{on: true, group: g, index: idx}
			}
		}
		e.serverSendData(sess, ps, wire.ClassBulk, false, seq, tag, ct)
	}
	return nil
}

// serverEmitParity schedules one parity shard of a session onto its paths.
func (e *Engine) serverEmitParity(sess *Session, group uint32, index, k, m uint8, shard []byte) {
	alive := sess.alivePaths(time.Now().UnixNano())
	if len(alive) == 0 {
		return
	}
	ps := alive[0]
	if len(alive) > 1 {
		ids := make([]uint8, len(alive))
		weights := make([]float64, len(alive))
		for i, u := range alive {
			ids[i] = u.id
			weights[i] = u.Link.Weight()
		}
		ps = alive[sess.wsched.Pick(ids, weights)]
	}
	slab := buffers.Get()
	defer buffers.Put(slab)
	f := wire.FECHeader{
		Header:   wire.Header{PathID: ps.id},
		Session:  sess.ID,
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
	if _, err := e.server.sock.WriteToUDPAddrPort((*slab)[:n+c], ps.addr); err == nil {
		e.Stats.TxPackets.Add(1)
		e.Stats.TxBytes.Add(uint64(n + c))
	}
}

func (e *Engine) serverSendData(sess *Session, ps *pathState, class uint8, dup bool, seq uint32, tag fecTag, ct []byte) {
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
		Header:    wire.Header{Type: wire.TypeData, Flags: flags, PathID: ps.id},
		Session:   sess.ID,
		GlobalSeq: seq,
		PathSeq:   sess.pathSeq[ps.id].Add(1),
		TxTS:      e.txTS(),
		FECGroup:  tag.group,
		FECIndex:  tag.index,
	}
	n := wire.PutDataHeader(*slab, &d)
	if n+len(ct) > len(*slab) {
		return
	}
	m := copy((*slab)[n:], ct)
	if _, err := e.server.sock.WriteToUDPAddrPort((*slab)[:n+m], ps.addr); err == nil {
		e.Stats.TxPackets.Add(1)
		e.Stats.TxBytes.Add(uint64(n + m))
	}
}
