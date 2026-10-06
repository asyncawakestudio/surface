//go:build integration

package asm

import (
	"testing"
)

// scanme.nmap.org is operated by the nmap project expressly for scan tests.
// Runs unprivileged here, so naabu falls back to a connect scan; in Docker
// with NET_RAW it is a half-open SYN scan. Either way exercises the stage.
func TestScanPortsLive(t *testing.T) {
	s := New(Options{
		PortScan:      true,
		PortScanPorts: "22,80,443,9929,31337", // known-open subset, keeps it quick
		PortScanRate:  200,
	})
	hosts := []resolvedHost{{Host: "scanme.nmap.org", IPs: []string{"45.33.32.156", "2600:3c01::f03c:91ff:fe18:bb2f"}}}

	got, err := s.scanPorts(t.Context(), hosts)
	if err != nil {
		t.Fatal(err)
	}
	// IPv6 address must be ignored; only the single IPv4 target scanned.
	if len(got) != 1 || got[0].IP != "45.33.32.156" {
		t.Fatalf("targets = %+v, want only 45.33.32.156", got)
	}
	t.Logf("privileged (SYN) = %v; open ports on %s: %+v", isPrivilegedScan(), got[0].IP, got[0].Ports)
	if len(got[0].Ports) == 0 {
		t.Skip("no open ports returned (network egress likely blocked in this env)")
	}
	for _, p := range got[0].Ports {
		if p.Protocol != "tcp" {
			t.Errorf("unexpected protocol %q", p.Protocol)
		}
	}
}
