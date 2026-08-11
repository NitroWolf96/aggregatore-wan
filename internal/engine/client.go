package engine

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
	"github.com/nitrowolf96/aggregatore-wan/internal/control"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Path is one WAN uplink: a UDP socket bound to that WAN's source address
// and connected to the aggregation server.
type Path struct {
	ID   uint8
	Name string

	conn       *net.UDPConn
	pathSeq    atomic.Uint32
	registered atomic.Bool
	lastRxNano atomic.Int64
	lastHello  atomic.Int64
}

// helloRetry is how often unregistered paths re-send HELLO; helloRefresh
// re-registers healthy paths so NAT bindings stay warm until PROBE
// keepalives arrive in M3.
const (
	helloRetry   = 1 * time.Second
	helloRefresh = 15 * time.Second
)

// AddPath creates the WAN socket for one uplink. bindIP may be empty (any
// source; useful in tests), otherwise it must be an address on the WAN's
// interface so policy routing steers the socket out of that WAN.
func (e *Engine) AddPath(name, bindIP, serverAddr string) (*Path, error) {
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("server address %s: %w", serverAddr, err)
	}
	var laddr *net.UDPAddr
	if bindIP != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(bindIP)}
		if laddr.IP == nil {
			return nil, fmt.Errorf("path %s: invalid bind address %q", name, bindIP)
		}
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("path %s: %w", name, err)
	}

	e.pathsMu.Lock()
	id := uint8(len(e.paths))
	p := &Path{ID: id, Name: name, conn: conn}
	e.paths = append(e.paths, p)
	e.pathsMu.Unlock()

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
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.helloLoop()
	}()
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

// activePath returns any usable path (used for readiness checks).
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

// sendablePaths snapshots the registered paths.
func (e *Engine) sendablePaths() []*Path {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	out := make([]*Path, 0, len(e.paths))
	for _, p := range e.paths {
		if p.registered.Load() {
			out = append(out, p)
		}
	}
	return out
}

// clientSend is the wgbridge SendFunc: WireGuard ciphertext leaves here,
// striped round-robin across the registered paths (the adaptive weighted
// scheduler replaces plain round-robin in milestone M3).
func (e *Engine) clientSend(bufs [][]byte, _ *wgbridge.SessionEndpoint) error {
	paths := e.sendablePaths()
	if len(paths) == 0 {
		e.Stats.TxDropNoPath.Add(uint64(len(bufs)))
		return nil
	}
	for _, ct := range bufs {
		p := paths[int(e.rr.Add(1))%len(paths)]
		e.sendDataOn(p, e.session, e.globalSeq.Add(1), ct)
	}
	return nil
}

// sendDataOn frames one ciphertext datagram and writes it to the path.
func (e *Engine) sendDataOn(p *Path, session, seq uint32, ct []byte) {
	slab := buffers.Get()
	defer buffers.Put(slab)
	d := wire.DataHeader{
		Header:    wire.Header{Type: wire.TypeData, PathID: p.ID},
		Session:   session,
		GlobalSeq: seq,
		PathSeq:   p.pathSeq.Add(1),
		TxTS:      e.txTS(),
	}
	n := wire.PutDataHeader(*slab, &d)
	if n+len(ct) > len(*slab) {
		e.Stats.RxDropMalformed.Add(1)
		return
	}
	m := copy((*slab)[n:], ct)
	if _, err := p.conn.Write((*slab)[:n+m]); err == nil {
		e.Stats.TxPackets.Add(1)
		e.Stats.TxBytes.Add(uint64(n + m))
	}
}

func (e *Engine) clientRxLoop(p *Path) {
	for {
		slab := buffers.Get()
		n, err := p.conn.Read(*slab)
		if err != nil {
			buffers.Put(slab)
			if e.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
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
	switch h.Type {
	case wire.TypeData:
		d, payload, err := wire.ParseDataHeader(dgram)
		if err != nil || d.Session != e.session {
			e.Stats.RxDropMalformed.Add(1)
			buffers.Put(slab)
			return
		}
		p.lastRxNano.Store(time.Now().UnixNano())
		e.Stats.RxPackets.Add(1)
		e.Stats.RxBytes.Add(uint64(n))
		pkt := buffers.Packet{Slab: slab, Off: d.Len(), Len: len(payload)}
		e.reorderBuf.Push(d.GlobalSeq, pkt)
	case wire.TypeHelloAck:
		if hh, m, ok := control.ParseHello(dgram, e.mac); ok &&
			hh.PathID == p.ID && m.Session == e.session && m.ClientID == e.clientID &&
			control.FreshTS(m.UnixTS, time.Now()) {
			if !p.registered.Swap(true) {
				e.log.Info("path registered", "path", p.Name, "id", p.ID)
			}
			p.lastRxNano.Store(time.Now().UnixNano())
		}
		buffers.Put(slab)
	default:
		// PROBE_ACK and CTRL land in milestone M3.
		buffers.Put(slab)
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
		e.pathsMu.RLock()
		paths := append([]*Path(nil), e.paths...)
		e.pathsMu.RUnlock()
		for _, p := range paths {
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
			p.conn.Write(dgram)
		}
	}
}

func (e *Engine) sendByes() {
	now := time.Now().Unix()
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for _, p := range e.paths {
		if p.registered.Load() {
			dgram := control.EncodeBye(wire.Header{PathID: p.ID}, control.Bye{Session: e.session, UnixTS: now}, e.mac)
			p.conn.Write(dgram)
		}
	}
}
