package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
	"github.com/nitrowolf96/aggregatore-wan/internal/control"
	"github.com/nitrowolf96/aggregatore-wan/internal/reorder"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// sessionTimeout removes sessions that have been completely silent.
const sessionTimeout = 5 * time.Minute

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
	addr   netip.AddrPort
	lastRx int64 // unix nanos of the last inbound datagram on this path
}

// pathStaleAfter excludes paths from return striping when nothing has
// arrived on them recently (idle paths still get a HELLO refresh every 15s).
const pathStaleAfter = 45 * time.Second

// Session is the server-side view of one client and its registered paths.
type Session struct {
	ID       uint32
	ClientID uint64
	Ep       *wgbridge.SessionEndpoint

	mu        sync.RWMutex
	paths     map[uint8]*pathState
	lastSeen  atomic.Int64
	globalSeq atomic.Uint32
	rr        atomic.Uint32
	pathSeq   [256]atomic.Uint32
	reorder   *reorder.Buffer[buffers.Packet]
}

func (s *Session) touchPath(pathID uint8, addr netip.AddrPort, now int64) {
	s.mu.Lock()
	ps := s.paths[pathID]
	if ps == nil {
		ps = &pathState{}
		s.paths[pathID] = ps
	}
	ps.addr = addr // per-path roaming: the newest source wins
	ps.lastRx = now
	s.mu.Unlock()
}

// alivePaths returns the ids and addresses of recently active paths.
func (s *Session) alivePaths(now int64) ([]uint8, []netip.AddrPort) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint8, 0, len(s.paths))
	addrs := make([]netip.AddrPort, 0, len(s.paths))
	cutoff := now - pathStaleAfter.Nanoseconds()
	for id, ps := range s.paths {
		if ps.lastRx >= cutoff {
			ids = append(ids, id)
			addrs = append(addrs, ps.addr)
		}
	}
	return ids, addrs
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
	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		e.serverRxLoop()
	}()
	go func() {
		defer e.wg.Done()
		e.sessionReaper()
	}()
	e.log.Info("listening", "addr", sock.LocalAddr())
	return nil
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
		now := time.Now().UnixNano()
		sess.touchPath(d.PathID, src, now)
		sess.lastSeen.Store(now)
		e.Stats.RxPackets.Add(1)
		e.Stats.RxBytes.Add(uint64(n))
		pkt := buffers.Packet{Slab: slab, Off: d.Len(), Len: len(payload)}
		sess.reorder.Push(d.GlobalSeq, pkt)
	case wire.TypeHello:
		e.handleHello(dgram, h, src)
		buffers.Put(slab)
	case wire.TypeBye:
		if _, m, ok := control.ParseBye(dgram, e.mac); ok && control.FreshTS(m.UnixTS, time.Now()) {
			e.removeSessionPath(m.Session, h.PathID)
		}
		buffers.Put(slab)
	default:
		buffers.Put(slab)
	}
}

func (e *Engine) handleHello(dgram []byte, h wire.Header, src netip.AddrPort) {
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

// serverSend is the wgbridge SendFunc of the server: return ciphertext is
// striped round-robin across the client's recently active paths (the
// adaptive weighted scheduler replaces plain round-robin in milestone M3).
func (e *Engine) serverSend(bufs [][]byte, ep *wgbridge.SessionEndpoint) error {
	sess := e.lookupSession(ep.Session)
	if sess == nil {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	ids, addrs := sess.alivePaths(time.Now().UnixNano())
	if len(ids) == 0 {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	for _, ct := range bufs {
		i := int(sess.rr.Add(1)) % len(ids)
		e.serverSendData(sess, ids[i], addrs[i], ct)
	}
	return nil
}

func (e *Engine) serverSendData(sess *Session, pathID uint8, addr netip.AddrPort, ct []byte) {
	slab := buffers.Get()
	defer buffers.Put(slab)
	d := wire.DataHeader{
		Header:    wire.Header{Type: wire.TypeData, PathID: pathID},
		Session:   sess.ID,
		GlobalSeq: sess.globalSeq.Add(1),
		PathSeq:   sess.pathSeq[pathID].Add(1),
		TxTS:      e.txTS(),
	}
	n := wire.PutDataHeader(*slab, &d)
	if n+len(ct) > len(*slab) {
		return
	}
	m := copy((*slab)[n:], ct)
	if _, err := e.server.sock.WriteToUDPAddrPort((*slab)[:n+m], addr); err == nil {
		e.Stats.TxPackets.Add(1)
		e.Stats.TxBytes.Add(uint64(n + m))
	}
}
