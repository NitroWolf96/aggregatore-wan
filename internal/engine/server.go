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

// Session is the server-side view of one client and its registered paths.
type Session struct {
	ID       uint32
	ClientID uint64
	Ep       *wgbridge.SessionEndpoint

	mu        sync.RWMutex
	addrs     map[uint8]netip.AddrPort
	active    atomic.Uint32 // path id of the most recent inbound packet
	lastSeen  atomic.Int64
	globalSeq atomic.Uint32
	pathSeq   [256]atomic.Uint32
}

func (s *Session) setAddr(pathID uint8, addr netip.AddrPort) {
	s.mu.Lock()
	if s.addrs[pathID] != addr {
		s.addrs[pathID] = addr
	}
	s.mu.Unlock()
}

func (s *Session) addr(pathID uint8) (netip.AddrPort, bool) {
	s.mu.RLock()
	a, ok := s.addrs[pathID]
	s.mu.RUnlock()
	return a, ok
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
		// Per-path roaming, like WireGuard: the newest source wins.
		sess.setAddr(d.PathID, src)
		sess.active.Store(uint32(d.PathID))
		sess.lastSeen.Store(time.Now().UnixNano())
		e.Stats.RxPackets.Add(1)
		e.Stats.RxBytes.Add(uint64(n))
		pkt := buffers.Packet{Slab: slab, Off: d.Len(), Len: len(payload)}
		if !e.bind.Deliver(pkt, sess.Ep) {
			e.Stats.RxDropQueue.Add(1)
		}
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
		sess = &Session{
			ID:       m.Session,
			ClientID: m.ClientID,
			Ep:       &wgbridge.SessionEndpoint{Session: m.Session},
			addrs:    make(map[uint8]netip.AddrPort),
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
	sess.setAddr(hh.PathID, src)
	sess.active.Store(uint32(hh.PathID))
	sess.lastSeen.Store(time.Now().UnixNano())

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
	delete(sess.addrs, pathID)
	empty := len(sess.addrs) == 0
	sess.mu.Unlock()
	if empty {
		e.server.mu.Lock()
		delete(e.server.sessions, sessionID)
		e.server.mu.Unlock()
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
				e.log.Info("session expired", "session", id)
			}
		}
		e.server.mu.Unlock()
	}
}

// serverSend is the wgbridge SendFunc of the server: return ciphertext is
// sent back to the client on the most recently active path (the scheduler
// takes over in milestone M2).
func (e *Engine) serverSend(bufs [][]byte, ep *wgbridge.SessionEndpoint) error {
	sess := e.lookupSession(ep.Session)
	if sess == nil {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	pathID := uint8(sess.active.Load())
	addr, ok := sess.addr(pathID)
	if !ok {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	for _, ct := range bufs {
		e.serverSendData(sess, pathID, addr, ct)
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
