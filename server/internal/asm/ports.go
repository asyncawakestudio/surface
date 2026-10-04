package asm

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

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

// scanPorts runs a naabu SYN scan across all TCP ports of every IPv4 address
// the hosts resolved to. IPv6 addresses are skipped per configuration.
//
// A SYN (half-open) scan needs raw-socket privileges (root or CAP_NET_RAW).
// Without them naabu falls back to a TCP connect scan on its own; we log the
// effective mode so the distinction is visible.
func (s *Scanner) scanPorts(ctx context.Context, hosts []resolvedHost) ([]PortScan, error) {
	ipToHosts := ipv4Hosts(hosts)
	if len(ipToHosts) == 0 {
		return nil, nil
	}

	targets := make([]string, 0, len(ipToHosts))
	for ip := range ipToHosts {
		targets = append(targets, ip)
	}
	sort.Strings(targets)

	// Collect results per IP from the callback, guarded by a mutex since
	// naabu invokes it from worker goroutines.
	var mu sync.Mutex
	portsByIP := make(map[string][]OpenPort, len(targets))

	options := &runner.Options{
		Host:               goflags.StringSlice(targets),
		Ports:              s.opts.PortScanPorts, // "-" == all 65535 TCP ports
		ScanType:           runner.SynScan,
		IPVersion:          goflags.StringSlice{"4"}, // IPv4 only
		Rate:               s.opts.PortScanRate,
		Retries:            s.opts.PortScanRetries,
		Threads:            s.opts.PortScanThreads,
		Timeout:            s.opts.PortScanTimeout,
		WithHostDiscovery:  false, // scan the IPs we already know are live
		DisableStdout:      true,
		Silent:             true,
		DisableUpdateCheck: true,
		OnResult: func(hr *result.HostResult) {
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				portsByIP[hr.IP] = append(portsByIP[hr.IP], OpenPort{
					Port:     p.Port,
					Protocol: p.Protocol.String(),
				})
			}
		},
	}

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("naabu init: %w", err)
	}
	defer naabuRunner.Close()

	s.opts.Logger.Info("ports: scanning",
		"ips", len(targets), "ports", s.opts.PortScanPorts, "privileged", isPrivilegedScan())

	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("naabu scan: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := make([]PortScan, 0, len(targets))
	for _, ip := range targets {
		ports := portsByIP[ip]
		slices.SortFunc(ports, func(a, b OpenPort) int {
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			return cmpString(a.Protocol, b.Protocol)
		})
		hosts := ipToHosts[ip]
		slices.Sort(hosts)
		out = append(out, PortScan{IP: ip, Hosts: hosts, Ports: ports})
	}
	return out, nil
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

// isPrivilegedScan reports whether the process can send raw packets, which a
// true SYN scan requires. naabu sets this at init from the OS capabilities.
func isPrivilegedScan() bool {
	return privileges.IsPrivileged
}
