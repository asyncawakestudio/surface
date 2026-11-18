//go:build !(windows && arm64)

package asm

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// PortScanSupported reports whether this build includes the naabu port
// scanner. windows/arm64 builds leave it out: naabu's packet capture
// dependency (gopacket/pcap) has no windows/arm64 support.
const PortScanSupported = true

// scanPorts runs a naabu scan (PortScanType, over PortScanPorts) of every
// IPv4 address the hosts resolved to. IPv6 addresses are skipped.
//
// A SYN (half-open) scan needs raw-socket privileges (root or CAP_NET_RAW).
// Without them naabu falls back to a TCP connect scan on its own; we log the
// effective mode so the distinction is visible.
//
// When probesFile is set, naabu also identifies the service on each open port
// (its -sV) and the result is attached to OpenPort.Service.
func (s *Scanner) scanPorts(ctx context.Context, hosts []resolvedHost, probesFile string) ([]PortScan, error) {
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

	scanType := runner.SynScan
	if strings.EqualFold(s.opts.PortScanType, "connect") {
		scanType = runner.ConnectScan
	}

	options := &runner.Options{
		Host:               goflags.StringSlice(targets),
		Ports:              s.opts.PortScanPorts, // "-" == all 65535 TCP ports
		ScanType:           scanType,
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
					Service:  serviceFromNaabu(p.Service),
				})
			}
		},
	}
	if probesFile != "" {
		// naabu fingerprints open ports after the scan and attaches the
		// results before calling OnResult. Note: enabling it also turns on
		// naabu's process-wide TLS detection for connect scans.
		options.ServiceVersion = true
		options.ServiceProbesFile = probesFile
		options.ServiceVersionTimeout = s.opts.ServiceTimeout
		options.ServiceVersionWorkers = s.opts.ServiceWorkers
	}

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("naabu init: %w", err)
	}
	defer naabuRunner.Close()

	s.opts.Logger.Info("ports: scanning",
		"ips", len(targets), "ports", s.opts.PortScanPorts,
		"type", scanType, "privileged", isPrivilegedScan(),
		"services", probesFile != "")

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

// isPrivilegedScan reports whether the process can send raw packets, which a
// true SYN scan requires. naabu sets this at init from the OS capabilities.
func isPrivilegedScan() bool {
	return privileges.IsPrivileged
}

// serviceProbesFile returns the nmap-service-probes file service detection
// will use: Options.ServiceProbesFile, or a local nmap installation's copy.
func (s *Scanner) serviceProbesFile() (string, error) {
	if path := s.opts.ServiceProbesFile; path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("service probes file: %w", err)
		}
		return path, nil
	}
	if path := fingerprint.LocateNmapProbes(); path != "" {
		return path, nil
	}
	return "", ErrServiceProbesNotFound
}

// serviceFromNaabu converts naabu's service match. It returns nil when there
// is no match.
func serviceFromNaabu(svc *port.Service) *Service {
	if svc == nil || svc.Name == "" {
		return nil
	}
	return &Service{
		Name:       svc.Name,
		Product:    svc.Product,
		Version:    svc.Version,
		ExtraInfo:  svc.ExtraInfo,
		TLS:        strings.EqualFold(svc.Tunnel, "ssl"),
		CPEs:       normalizeCPEs(svc.CPEs),
		Confidence: svc.Confidence,
		Banner:     truncateBanner(svc.Banner),
	}
}
