//go:build integration

package asm

import "testing"

func TestConnectAllPortsVsSubset(t *testing.T) {
	ip := "185.199.108.153" // GitHub Pages, 80/443 open
	for _, ports := range []string{"80,443", "1-1000", "-"} {
		s := New(Options{PortScan: true, PortScanType: "connect", PortScanPorts: ports, PortScanRetries: 1})
		got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "x", IPs: []string{ip}}})
		if err != nil {
			t.Fatalf("ports=%s: %v", ports, err)
		}
		n := 0
		if len(got) == 1 {
			n = len(got[0].Ports)
		}
		t.Logf("ports=%-7s open=%d %+v", ports, n, func() []OpenPort { if len(got)==1 {return got[0].Ports}; return nil }())
	}
}
