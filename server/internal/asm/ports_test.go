package asm

import (
	"slices"
	"strings"
	"testing"
)

func TestIPv4Hosts(t *testing.T) {
	hosts := []resolvedHost{
		{Host: "a.example.com", IPs: []string{"93.184.215.14", "2606:2800::1"}},
		{Host: "b.example.com", IPs: []string{"93.184.215.14"}},           // shared IPv4
		{Host: "c.example.com", IPs: []string{"2606:2800::2"}},            // IPv6 only -> skipped
		{Host: "d.example.com", IPs: []string{"10.0.0.1", "not-an-ip"}},   // private kept, junk skipped
		{Host: "a.example.com", IPs: []string{"93.184.215.14"}},          // duplicate host+ip
	}
	got := ipv4Hosts(hosts)

	if len(got) != 2 {
		t.Fatalf("got %d IPv4 targets, want 2: %v", len(got), got)
	}
	shared := got["93.184.215.14"]
	slices.Sort(shared)
	if strings.Join(shared, ",") != "a.example.com,b.example.com" {
		t.Errorf("hosts for shared IP = %v", shared)
	}
	if _, ok := got["10.0.0.1"]; !ok {
		t.Error("private IPv4 was dropped")
	}
	for ip := range got {
		if strings.Contains(ip, ":") {
			t.Errorf("IPv6 address %q present", ip)
		}
	}
}

func TestScanPortsNoIPv4(t *testing.T) {
	// Only IPv6 resolved: naabu must not be invoked and no error returned.
	s := New(Options{PortScan: true})
	got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "v6.example.com", IPs: []string{"2606:2800::1"}}})
	if err != nil || got != nil {
		t.Fatalf("scanPorts = %v, %v; want nil, nil", got, err)
	}
}
