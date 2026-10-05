//go:build integration

package asm

import "testing"

func TestConnectAllPortsRate(t *testing.T) {
	for _, rate := range []int{100, 500, 1000} {
		s := New(Options{PortScan: true, PortScanType: "connect", PortScanPorts: "-", PortScanRate: rate, PortScanRetries: 2})
		got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "x", IPs: []string{"185.199.108.153"}}})
		if err != nil {
			t.Fatalf("rate=%d: %v", rate, err)
		}
		n := 0
		if len(got) == 1 {
			n = len(got[0].Ports)
		}
		t.Logf("rate=%-5d all-ports open=%d", rate, n)
	}
}
