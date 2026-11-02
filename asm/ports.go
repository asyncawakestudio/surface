package asm

import (
	"errors"
	"net/netip"
)

// ErrPortScanUnsupported is returned when a port scan is requested on a
// platform without one (see PortScanSupported).
var ErrPortScanUnsupported = errors.New("port scanning is not supported on this platform")

// OpenPort is a single open port found on an IP.
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// PortScan is the set of open ports found on one IPv4 address, with the
// hosts that resolved to it.
type PortScan struct {
	IP    string     `json:"ip"`
	Hosts []string   `json:"hosts"`
	Ports []OpenPort `json:"ports"`
}

// ipv4Hosts maps each unique IPv4 address to the sorted, de-duplicated list
// of hosts that resolved to it. IPv6 addresses are ignored.
func ipv4Hosts(hosts []resolvedHost) map[string][]string {
	out := map[string]map[string]struct{}{}
	for _, h := range hosts {
		for _, raw := range h.IPs {
			addr, err := netip.ParseAddr(raw)
			if err != nil || !addr.Is4() {
				continue
			}
			ip := addr.String()
			if out[ip] == nil {
				out[ip] = map[string]struct{}{}
			}
			out[ip][h.Host] = struct{}{}
		}
	}
	m := make(map[string][]string, len(out))
	for ip, set := range out {
		hs := make([]string, 0, len(set))
		for h := range set {
			hs = append(hs, h)
		}
		m[ip] = hs
	}
	return m
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
