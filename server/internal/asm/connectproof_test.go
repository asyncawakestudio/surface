//go:build integration

package asm

import "testing"

// Connect scan must find open ports through NAT (e.g. a Docker bridge), where
// a raw SYN scan's replies may not return. scanme.nmap.org authorizes scans.
func TestConnectScanFindsPorts(t *testing.T) {
	s := New(Options{PortScan: true, PortScanType: "connect", PortScanPorts: "22,80", PortScanRetries: 1})
	got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "scanme.nmap.org", IPs: []string{"45.33.32.156"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Ports) == 0 {
		t.Fatalf("connect scan found no ports: %+v", got)
	}
	t.Logf("connect scan open ports: %+v", got[0].Ports)
}
