// Command treccia-client is the WAN-side bonding daemon: it owns the TUN
// interface, encrypts traffic with an embedded WireGuard instance and stripes
// the resulting ciphertext across every available WAN link toward a
// treccia-server aggregation endpoint.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	fmt.Printf("treccia-client %s (scaffold, see milestone M1)\n", version)
	os.Exit(0)
}
