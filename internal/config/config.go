// Package config loads and validates the YAML configuration of the Treccia
// daemons.
package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/nitrowolf96/aggregatore-wan/internal/classify"
	"github.com/nitrowolf96/aggregatore-wan/internal/fec"
)

// DefaultMTU is the tunnel MTU: 1428 (typical 4G APN MTU) minus the worst
// case outer overhead of 84 bytes (IP 20 + UDP 8 + Treccia 24 + WireGuard
// 32). It is a multiple of 16, so full-size packets need no WireGuard
// padding.
const DefaultMTU = 1344

// Tunnel describes the inner WireGuard interface of either side.
type Tunnel struct {
	Interface     string   `yaml:"interface"`
	MTU           int      `yaml:"mtu"`
	Address       string   `yaml:"address"` // CIDR, e.g. 10.200.0.2/24
	PrivateKey    string   `yaml:"private_key"`
	PeerPublicKey string   `yaml:"peer_public_key"`
	Routes        []string `yaml:"routes"` // extra CIDRs routed into the tunnel
}

// Path is one WAN uplink of the client.
type Path struct {
	Name string `yaml:"name"`
	Bind string `yaml:"bind"` // local source IP on that WAN
}

// Dashboard configures the embedded metrics endpoint.
type Dashboard struct {
	Listen string `yaml:"listen"` // empty disables it
	Token  string `yaml:"token"`  // optional bearer token
}

// FEC configures forward error correction of the bulk stream.
type FEC struct {
	Disabled bool   `yaml:"disabled"`
	Force    string `yaml:"force"` // fixed "k:m" geometry; empty = adaptive
}

// Params resolves the forced geometry (zero when adaptive).
func (f *FEC) Params() (fec.Params, error) {
	if f.Force == "" {
		return fec.Params{}, nil
	}
	return fec.ParseForce(f.Force)
}

// Classify configures per-flow classification.
type Classify struct {
	Disabled bool            `yaml:"disabled"`
	Rules    []classify.Rule `yaml:"rules"`
}

func (c *Classify) validate() error {
	for i, r := range c.Rules {
		if _, ok := classify.ParseClass(r.Class); !ok {
			return fmt.Errorf("classify.rules[%d].class %q: want bulk, realtime or interactive", i, r.Class)
		}
		if r.Port == 0 {
			return fmt.Errorf("classify.rules[%d]: port is required", i)
		}
		switch r.Proto {
		case "tcp", "udp", "any", "":
		default:
			return fmt.Errorf("classify.rules[%d].proto %q: want tcp, udp or any", i, r.Proto)
		}
	}
	return nil
}

// Client is the configuration of treccia-client.
type Client struct {
	Tunnel     Tunnel    `yaml:"tunnel"`
	ServerAddr string    `yaml:"server_addr"`
	ControlPSK string    `yaml:"control_psk"`
	Paths      []Path    `yaml:"paths"`
	Classify   Classify  `yaml:"classify"`
	FEC        FEC       `yaml:"fec"`
	Dashboard  Dashboard `yaml:"dashboard"`
}

// Server is the configuration of treccia-server.
type Server struct {
	Tunnel     Tunnel    `yaml:"tunnel"`
	Listen     string    `yaml:"listen"`
	ControlPSK string    `yaml:"control_psk"`
	Classify   Classify  `yaml:"classify"`
	FEC        FEC       `yaml:"fec"`
	Dashboard  Dashboard `yaml:"dashboard"`
}

func (t *Tunnel) applyDefaults(iface string) {
	if t.Interface == "" {
		t.Interface = iface
	}
	if t.MTU == 0 {
		t.MTU = DefaultMTU
	}
}

func (t *Tunnel) validate() error {
	if t.PrivateKey == "" {
		return fmt.Errorf("tunnel.private_key is required (generate one with the genkey subcommand)")
	}
	if t.PeerPublicKey == "" {
		return fmt.Errorf("tunnel.peer_public_key is required")
	}
	if _, err := netip.ParsePrefix(t.Address); err != nil {
		return fmt.Errorf("tunnel.address: %w", err)
	}
	for _, r := range t.Routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			return fmt.Errorf("tunnel.routes %q: %w", r, err)
		}
	}
	if t.MTU < 576 || t.MTU > 1420 {
		return fmt.Errorf("tunnel.mtu %d out of range [576, 1420]", t.MTU)
	}
	return nil
}

// LoadClient reads and validates a client configuration file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, err
	}
	c.Tunnel.applyDefaults("treccia0")
	if err := c.Tunnel.validate(); err != nil {
		return nil, err
	}
	if c.ServerAddr == "" {
		return nil, fmt.Errorf("server_addr is required")
	}
	if c.ControlPSK == "" {
		return nil, fmt.Errorf("control_psk is required")
	}
	if len(c.Paths) == 0 {
		return nil, fmt.Errorf("at least one entry in paths is required")
	}
	if len(c.Paths) > 250 {
		return nil, fmt.Errorf("too many paths (max 250)")
	}
	if err := c.Classify.validate(); err != nil {
		return nil, err
	}
	if _, err := c.FEC.Params(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range c.Paths {
		p := &c.Paths[i]
		if p.Name == "" {
			p.Name = fmt.Sprintf("path%d", i)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("duplicate path name %q", p.Name)
		}
		seen[p.Name] = true
		if p.Bind != "" {
			if _, err := netip.ParseAddr(p.Bind); err != nil {
				return nil, fmt.Errorf("paths[%d].bind: %w", i, err)
			}
		}
	}
	return &c, nil
}

// LoadServer reads and validates a server configuration file.
func LoadServer(path string) (*Server, error) {
	var s Server
	if err := load(path, &s); err != nil {
		return nil, err
	}
	s.Tunnel.applyDefaults("treccia0")
	if err := s.Tunnel.validate(); err != nil {
		return nil, err
	}
	if s.Listen == "" {
		s.Listen = ":51820"
	}
	if s.ControlPSK == "" {
		return nil, fmt.Errorf("control_psk is required")
	}
	if err := s.Classify.validate(); err != nil {
		return nil, err
	}
	if _, err := s.FEC.Params(); err != nil {
		return nil, err
	}
	return &s, nil
}

func load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
