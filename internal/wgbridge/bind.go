// Package wgbridge embeds wireguard-go and bridges it to the Treccia
// multipath engine: a custom conn.Bind replaces the UDP socket WireGuard
// would normally own, and a TUN shim exposes the plaintext to the flow
// classifier before encryption.
package wgbridge

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/nitrowolf96/aggregatore-wan/internal/buffers"
)

// SessionEndpoint is the conn.Endpoint we hand to wireguard-go. It carries
// the Treccia session id instead of a network address: the engine, not
// WireGuard, decides which WAN socket a datagram leaves from.
type SessionEndpoint struct {
	Session uint32
}

var _ conn.Endpoint = (*SessionEndpoint)(nil)

func (e *SessionEndpoint) ClearSrc()           {}
func (e *SessionEndpoint) SrcToString() string { return "" }
func (e *SessionEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *SessionEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *SessionEndpoint) DstToString() string {
	return fmt.Sprintf("session:%d", e.Session)
}

// DstToBytes feeds WireGuard's cookie MAC; it only needs to be stable per
// endpoint.
func (e *SessionEndpoint) DstToBytes() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, e.Session)
	return b
}

// SendFunc receives WireGuard ciphertext datagrams bound for the peer of
// the given session and must schedule them onto WAN sockets.
type SendFunc func(bufs [][]byte, ep *SessionEndpoint) error

// Inbound is one ciphertext datagram the engine delivers up to WireGuard.
type Inbound struct {
	Pkt buffers.Packet
	Ep  *SessionEndpoint
}

// EngineBind implements conn.Bind on top of the multipath engine.
type EngineBind struct {
	send SendFunc

	mu     sync.Mutex
	rx     chan Inbound
	closed bool
}

var _ conn.Bind = (*EngineBind)(nil)

// rxQueueLen bounds ciphertext waiting for WireGuard to pick it up. At MTU
// size this is ~2 MB, a couple of RTTs at 1 Gbps.
const rxQueueLen = 1024

func NewEngineBind(send SendFunc) *EngineBind {
	return &EngineBind{send: send}
}

func (b *EngineBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rx != nil && !b.closed {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.rx = make(chan Inbound, rxQueueLen)
	b.closed = false
	rx := b.rx
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		in, ok := <-rx
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(packets[0], in.Pkt.Bytes())
		sizes[0] = n
		eps[0] = in.Ep
		in.Pkt.Release()
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *EngineBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rx != nil && !b.closed {
		b.closed = true
		close(b.rx)
	}
	return nil
}

func (b *EngineBind) SetMark(uint32) error { return nil }

func (b *EngineBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	se, ok := ep.(*SessionEndpoint)
	if !ok {
		return fmt.Errorf("wgbridge: unexpected endpoint type %T", ep)
	}
	return b.send(bufs, se)
}

// ParseEndpoint accepts the placeholder endpoint string used in the client
// UAPI config; the engine routes by session, not by address.
func (b *EngineBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return &SessionEndpoint{}, nil
}

func (b *EngineBind) BatchSize() int { return 1 }

// Deliver hands one ciphertext datagram up to WireGuard. It takes ownership
// of pkt. It never blocks: if WireGuard's receive queue is full the packet
// is dropped (the inner protocols recover) and false is returned. The lock
// is held across the non-blocking enqueue so Close can never close the
// channel mid-send.
func (b *EngineBind) Deliver(pkt buffers.Packet, ep *SessionEndpoint) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rx == nil || b.closed {
		pkt.Release()
		return false
	}
	select {
	case b.rx <- Inbound{Pkt: pkt, Ep: ep}:
		return true
	default:
		pkt.Release()
		return false
	}
}
