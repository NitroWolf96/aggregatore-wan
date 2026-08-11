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

	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Mode selects the client or server role of the engine.
type Mode int

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
	Mode     Mode
	MAC      *wire.MAC
	Session  uint32 // client only: the session id it will register
	ClientID uint64 // client only: random identity echoed in HELLO_ACK
	Logger   *slog.Logger
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

	// Client state.
	pathsMu   sync.RWMutex
	paths     []*Path
	clientEp  *wgbridge.SessionEndpoint
	globalSeq atomic.Uint32

	// Server state.
	server *serverState
}

// New builds an engine; Run starts its loops.
func New(cfg Config) *Engine {
	e := &Engine{
		mode:     cfg.Mode,
		log:      cfg.Logger,
		mac:      cfg.MAC,
		start:    time.Now(),
		session:  cfg.Session,
		clientID: cfg.ClientID,
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if cfg.Mode == ModeClient {
		e.clientEp = &wgbridge.SessionEndpoint{Session: cfg.Session}
		e.bind = wgbridge.NewEngineBind(e.clientSend)
	} else {
		e.server = newServerState()
		e.bind = wgbridge.NewEngineBind(e.serverSend)
	}
	return e
}

// Bind returns the conn.Bind to hand to wireguard-go.
func (e *Engine) Bind() *wgbridge.EngineBind { return e.bind }

// txTS returns the sender clock in microseconds, truncated to 32 bits.
func (e *Engine) txTS() uint32 {
	return uint32(time.Since(e.start).Microseconds())
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
		p.conn.Close()
	}
	e.pathsMu.RUnlock()
	if e.server != nil && e.server.sock != nil {
		e.server.sock.Close()
	}
	e.wg.Wait()
}
