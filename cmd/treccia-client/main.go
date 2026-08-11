// Command treccia-client is the WAN-side bonding daemon: it owns the TUN
// interface, encrypts traffic with an embedded WireGuard instance and stripes
// the resulting ciphertext across every available WAN link toward a
// treccia-server aggregation endpoint.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/cli"
	"github.com/nitrowolf96/aggregatore-wan/internal/config"
	"github.com/nitrowolf96/aggregatore-wan/internal/engine"
	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

var version = "dev"

func main() {
	if cli.KeySubcommand(os.Args[1:]) {
		return
	}
	fs := flag.NewFlagSet("treccia-client", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/treccia/client.yaml", "configuration file")
	verbose := fs.Bool("verbose", false, "debug logging")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println("treccia-client", version)
		return
	}

	log := cli.NewLogger(*verbose)
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		log.Error("entropy", "err", err)
		os.Exit(1)
	}
	session := binary.BigEndian.Uint32(rnd[0:4]) | 1 // never zero
	clientID := binary.BigEndian.Uint64(rnd[4:12])

	eng := engine.New(engine.Config{
		Mode:     engine.ModeClient,
		MAC:      wire.NewMAC(wire.DeriveKey(cfg.ControlPSK)),
		Session:  session,
		ClientID: clientID,
		Logger:   log,
	})

	wg, err := wgbridge.NewWG(cfg.Tunnel, eng.Bind(), nil, log, true)
	if err != nil {
		log.Error("wireguard", "err", err)
		os.Exit(1)
	}
	defer wg.Close()

	name, err := wg.Tun.Name()
	if err != nil {
		name = cfg.Tunnel.Interface
	}
	if err := wgbridge.SetupNetdev(name, cfg.Tunnel.Address, cfg.Tunnel.Routes); err != nil {
		log.Error("netdev", "err", err)
		os.Exit(1)
	}

	for _, p := range cfg.Paths {
		if _, err := eng.AddPath(p.Name, p.Bind, cfg.ServerAddr); err != nil {
			log.Error("path", "name", p.Name, "err", err)
			os.Exit(1)
		}
	}
	eng.Run()
	defer eng.Close()

	if err := eng.WaitReady(10 * time.Second); err != nil {
		log.Warn("no path registered yet, continuing anyway", "err", err)
	}
	if err := wg.Up(); err != nil {
		log.Error("wireguard up", "err", err)
		os.Exit(1)
	}
	log.Info("treccia-client up", "version", version, "session", session, "tun", name, "paths", len(cfg.Paths))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
}
