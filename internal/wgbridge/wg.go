package wgbridge

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/nitrowolf96/aggregatore-wan/internal/config"
)

// WG bundles the embedded wireguard-go instance and its TUN device.
type WG struct {
	Dev *device.Device
	Tun tun.Device
}

// NewWG creates the TUN interface, wires it (through the shim) and the
// engine bind into a wireguard-go device, and configures keys and the
// single peer. isClient adds the placeholder endpoint so this side
// initiates handshakes. The device is created down; call Up after the
// engine is ready.
func NewWG(cfg config.Tunnel, bind conn.Bind, inspect InspectFunc, log *slog.Logger, isClient bool) (*WG, error) {
	priv, err := ParseKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	peer, err := ParseKey(cfg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("peer public key: %w", err)
	}

	tundev, err := tun.CreateTUN(cfg.Interface, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %s: %w", cfg.Interface, err)
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug("wg: " + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			log.Error("wg: " + fmt.Sprintf(format, args...))
		},
	}

	dev := device.NewDevice(NewTunShim(tundev, inspect), bind, logger)

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", priv.Hex())
	fmt.Fprintf(&uapi, "public_key=%s\n", peer.Hex())
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")
	if isClient {
		// The engine routes by session, the endpoint string is a placeholder.
		uapi.WriteString("endpoint=treccia\n")
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg config: %w", err)
	}

	return &WG{Dev: dev, Tun: tundev}, nil
}

// Up brings the WireGuard device up (this opens the bind).
func (w *WG) Up() error { return w.Dev.Up() }

// Close tears down the device and the TUN interface.
func (w *WG) Close() {
	w.Dev.Close()
}
