package wgbridge

import "golang.zx2c4.com/wireguard/tun"

// InspectFunc sees every outbound plaintext IP packet just before WireGuard
// encrypts it. The flow classifier (milestone M4) hooks in here; the packet
// must not be retained or modified.
type InspectFunc func(pkt []byte)

// TunShim wraps the real TUN device so Treccia can observe plaintext on the
// outbound path while wireguard-go keeps seeing a plain tun.Device.
type TunShim struct {
	tun.Device
	inspect InspectFunc
}

func NewTunShim(dev tun.Device, inspect InspectFunc) *TunShim {
	return &TunShim{Device: dev, inspect: inspect}
}

func (t *TunShim) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	if t.inspect != nil {
		for i := 0; i < n; i++ {
			t.inspect(bufs[i][offset : offset+sizes[i]])
		}
	}
	return n, err
}
