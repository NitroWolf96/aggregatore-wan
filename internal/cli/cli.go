// Package cli holds the small helpers shared by the treccia-client and
// treccia-server commands.
package cli

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/nitrowolf96/aggregatore-wan/internal/wgbridge"
)

// NewLogger builds the process logger.
func NewLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// KeySubcommand implements the genkey/pubkey subcommands shared by both
// binaries. It returns true when it handled the invocation.
func KeySubcommand(args []string) bool {
	if len(args) < 1 {
		return false
	}
	switch args[0] {
	case "genkey":
		k, err := wgbridge.GeneratePrivateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "genkey:", err)
			os.Exit(1)
		}
		fmt.Println(k.String())
	case "pubkey":
		in := bufio.NewScanner(os.Stdin)
		if !in.Scan() {
			fmt.Fprintln(os.Stderr, "pubkey: expected a private key on stdin")
			os.Exit(1)
		}
		k, err := wgbridge.ParseKey(strings.TrimSpace(in.Text()))
		if err != nil {
			fmt.Fprintln(os.Stderr, "pubkey:", err)
			os.Exit(1)
		}
		pub, err := k.PublicKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "pubkey:", err)
			os.Exit(1)
		}
		fmt.Println(pub.String())
	default:
		return false
	}
	return true
}
