//go:build integration

package asm

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
)

// Reproduce the container condition: privileged process doing a CONNECT scan.
func TestConnectScanWhilePrivileged(t *testing.T) {
	orig := privileges.IsPrivileged
	privileges.IsPrivileged = true
	t.Cleanup(func() { privileges.IsPrivileged = orig })

	for _, ports := range []string{"80,443", "-"} {
		s := New(Options{PortScan: true, PortScanType: "connect", PortScanPorts: ports, PortScanRetries: 1})
		got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "x", IPs: []string{"185.199.108.153"}}})
		if err != nil {
			t.Fatalf("ports=%s: %v", ports, err)
		}
		n := 0
		if len(got) == 1 {
			n = len(got[0].Ports)
		}
		t.Logf("privileged=true ports=%-5s open=%d", ports, n)
	}
}
