// Package engine implements the Treccia multipath datapath: it owns the WAN
// UDP sockets on the client and the single aggregation socket on the server,
// frames WireGuard ciphertext with the wire protocol, and (as milestones
// land) schedules, reorders, duplicates and FEC-protects packets across
// paths. WireGuard talks to the engine through wgbridge.EngineBind.
package engine

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
	"github.com/nitrowolf96/aggregatore-wan/internal/classify"
	"github.com/nitrowolf96/aggregatore-wan/internal/fec"
	"github.com/nitrowolf96/aggregatore-wan/internal/pathmon"
	"github.com/nitrowolf96/aggregatore-wan/internal/reorder"
	"github.com/nitrowolf96/aggregatore-wan/internal/sched"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Mode selects the client or server role of the engine.
type Mode int

// fecTag carries the FEC group assignment of one outgoing bulk packet.
type fecTag struct {
	on    bool
	group uint32
	index uint8
}

const (
	ModeClient Mode = iota
	ModeServer
)

// Counters are the engine-wide datapath counters, all atomically updated.
type Counters struct {
	TxPackets       atomic.Uint64
	TxBytes         atomic.Uint64
	RxPackets       atomic.Uint64
	RxBytes         atomic.Uint64
	TxDropNoPath    atomic.Uint64 // ciphertext dropped: no registered path yet
	RxDropUnknown   atomic.Uint64 // datagrams for unknown sessions/paths
	RxDropQueue     atomic.Uint64 // WireGuard receive queue full
	RxDropMalformed atomic.Uint64
}

// Config parametrizes a new engine.
type Config struct {
	Mode        Mode
	MAC         *wire.MAC
	Session     uint32 // client only: the session id it will register
	ClientID    uint64 // client only: random identity echoed in HELLO_ACK
	Logger      *slog.Logger
	Classifier  *classify.Classifier // nil disables classification (all bulk)
	FECDisabled bool
	FECForce    fec.Params // fixed geometry override; zero = adaptive
}

// Engine is one side of the multipath tunnel.
type Engine struct {
	mode     Mode
	log      *slog.Logger
	mac      *wire.MAC
	bind     *wgbridge.EngineBind
	start    time.Time
	session  uint32
	clientID uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	Stats Counters

	classifier *classify.Classifier
	correlator *wgbridge.Correlator
	rtSeq      atomic.Uint32 // sequence pool for non-bulk packets (stats/dup only)

	fecDisabled bool
	fecForce    fec.Params
	fecEnc      *fec.Encoder // client TX; server sessions have their own
	fecDec      *fec.Decoder // client RX

	// Client state.
	pathsMu    sync.RWMutex
	paths      []*Path
	clientEp   *wgbridge.SessionEndpoint
	globalSeq  atomic.Uint32
	wsched     *sched.Weighted
	reorderBuf *reorder.Buffer[buffers.Packet]

	// Server state.
	server *serverState
}

// New builds an engine; Run starts its loops.
func New(cfg Config) *Engine {
	e := &Engine{
		mode:        cfg.Mode,
		log:         cfg.Logger,
		mac:         cfg.MAC,
		start:       time.Now(),
		session:     cfg.Session,
		clientID:    cfg.ClientID,
		classifier:  cfg.Classifier,
		correlator:  &wgbridge.Correlator{},
		fecDisabled: cfg.FECDisabled,
		fecForce:    cfg.FECForce,
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if cfg.Mode == ModeClient {
		e.clientEp = &wgbridge.SessionEndpoint{Session: cfg.Session}
		e.bind = wgbridge.NewEngineBind(e.clientSend)
		e.reorderBuf = e.newReorder(e.clientEp)
		e.wsched = sched.NewWeighted()
		if !cfg.FECDisabled {
			e.fecEnc = fec.NewEncoder(e.clientEmitParity)
			e.fecEnc.SetParams(cfg.FECForce)
			e.fecDec = fec.NewDecoder(func(seq uint32, ct []byte) {
				slab := buffers.Get()
				n := copy(*slab, ct)
				e.reorderBuf.Push(seq, buffers.Packet{Slab: slab, Len: n})
			})
		}
	} else {
		e.server = newServerState()
		e.bind = wgbridge.NewEngineBind(e.serverSend)
	}
	return e
}

// retuneFEC applies the adaptive controller (or the forced geometry) to
// one encoder given the current path snapshots.
func (e *Engine) retuneFEC(enc *fec.Encoder, snaps []pathmon.Snapshot) {
	if enc == nil {
		return
	}
	params := e.fecForce
	if params.K == 0 {
		params = fec.PickParams(pathmon.WeightedLoss(snaps))
	}
	enc.SetParams(params)
}

// newReorder builds a resequencing buffer that releases ciphertext (in
// order, or as late passthrough) up to WireGuard for the given endpoint.
func (e *Engine) newReorder(ep *wgbridge.SessionEndpoint) *reorder.Buffer[buffers.Packet] {
	return reorder.New(
		func(pkt buffers.Packet, _ bool) {
			if !e.bind.Deliver(pkt, ep) {
				e.Stats.RxDropQueue.Add(1)
			}
		},
		func(pkt buffers.Packet) { pkt.Release() },
		nil,
	)
}

// Bind returns the conn.Bind to hand to wireguard-go.
func (e *Engine) Bind() *wgbridge.EngineBind { return e.bind }

// Inspect returns the TUN-shim hook that classifies outbound plaintext and
// feeds the plaintext->ciphertext correlator; nil when classification is
// disabled.
func (e *Engine) Inspect() wgbridge.InspectFunc {
	if e.classifier == nil {
		return nil
	}
	return func(pkt []byte) {
		e.correlator.PushPlain(e.classifier.Classify(pkt), len(pkt))
	}
}

// classifyCt maps one outbound WireGuard datagram to its traffic class.
// Handshakes and keepalives ride the lowest-latency path; transport data
// takes the class recorded by the correlator.
func (e *Engine) classifyCt(ct []byte) uint8 {
	if len(ct) < 4 {
		return wire.ClassInteractive
	}
	if ct[0] != 4 { // handshake initiation/response/cookie
		return wire.ClassInteractive
	}
	if len(ct) == 32 { // keepalive: empty transport payload
		return wire.ClassInteractive
	}
	if e.classifier == nil {
		return wire.ClassBulk
	}
	return e.correlator.MatchCiphertext(len(ct))
}

// txTS returns the sender clock in microseconds, truncated to 32 bits.
func (e *Engine) txTS() uint32 {
	return uint32(time.Since(e.start).Microseconds())
}

// nowUS returns the sender clock in microseconds (full width, for probes).
func (e *Engine) nowUS() uint64 {
	return uint64(time.Since(e.start).Microseconds())
}

// Close stops all loops and sockets. On the client a best-effort BYE is
// sent on every registered path first.
func (e *Engine) Close() {
	if e.mode == ModeClient {
		e.sendByes()
	}
	e.cancel()
	e.pathsMu.RLock()
	for _, p := range e.paths {
		p.close()
	}
	e.pathsMu.RUnlock()
	if e.server != nil && e.server.sock != nil {
		e.server.sock.Close()
	}
	e.wg.Wait()
	if e.reorderBuf != nil {
		e.reorderBuf.Close()
	}
	if e.server != nil {
		e.server.mu.Lock()
		for _, s := range e.server.sessions {
			s.reorder.Close()
		}
		e.server.mu.Unlock()
	}
}
