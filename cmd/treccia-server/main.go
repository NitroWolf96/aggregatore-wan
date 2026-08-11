// Command treccia-server is the aggregation endpoint: it terminates the
// multipath tunnel on a single UDP port, reorders and deduplicates the
// striped ciphertext, decrypts it with an embedded WireGuard instance and
// NATs the inner traffic to the internet.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	fmt.Printf("treccia-server %s (scaffold, see milestone M1)\n", version)
	os.Exit(0)
}
