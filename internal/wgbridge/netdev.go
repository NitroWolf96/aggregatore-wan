package wgbridge

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// SetupNetdev assigns the address to the TUN interface, brings it up and
// installs the extra routes pointing into the tunnel.
func SetupNetdev(iface, addrCIDR string, routes []string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	addr, err := netlink.ParseAddr(addrCIDR)
	if err != nil {
		return fmt.Errorf("address %s: %w", addrCIDR, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add address %s: %w", addrCIDR, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	for _, r := range routes {
		_, dst, err := net.ParseCIDR(r)
		if err != nil {
			return fmt.Errorf("route %s: %w", r, err)
		}
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add route %s: %w", r, err)
		}
	}
	return nil
}
