// Command treccia-server is the aggregation endpoint: it terminates the
// multipath tunnel on a single UDP port, reorders and deduplicates the
// striped ciphertext, decrypts it with an embedded WireGuard instance and
// forwards the inner traffic (NAT is configured by the host, see deploy/).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nitrowolf96/aggregatore-wan/internal/classify"
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
	fs := flag.NewFlagSet("treccia-server", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/treccia/server.yaml", "configuration file")
	verbose := fs.Bool("verbose", false, "debug logging")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println("treccia-server", version)
		return
	}

	log := cli.NewLogger(*verbose)
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	var classifier *classify.Classifier
	if !cfg.Classify.Disabled {
		classifier = classify.New(cfg.Classify.Rules)
	}
	eng := engine.New(engine.Config{
		Mode:       engine.ModeServer,
		MAC:        wire.NewMAC(wire.DeriveKey(cfg.ControlPSK)),
		Logger:     log,
		Classifier: classifier,
	})

	wg, err := wgbridge.NewWG(cfg.Tunnel, eng.Bind(), eng.Inspect(), log, false)
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

	if err := eng.Listen(cfg.Listen); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	defer eng.Close()

	if err := wg.Up(); err != nil {
		log.Error("wireguard up", "err", err)
		os.Exit(1)
	}
	log.Info("treccia-server up", "version", version, "tun", name, "listen", cfg.Listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
}
