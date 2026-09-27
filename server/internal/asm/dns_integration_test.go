//go:build integration

// Live DNS test: go test -tags integration -run TestResolveLive -v ./internal/asm
package asm

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestResolveLive(t *testing.T) {
	live := []string{"wikipedia.org", "www.wikipedia.org", "en.wikipedia.org"}
	hosts := append([]string{}, live...)
	for i := range 150 {
		hosts = append(hosts, fmt.Sprintf("surface-nx-%d.wikipedia.org", i))
	}

	s := New(Options{})
	start := time.Now()
	records, resolved, err := s.resolve(context.Background(), "wikipedia.org", hosts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resolved %d/%d hosts, %d records in %s", len(resolved), len(hosts), len(records), time.Since(start).Round(time.Millisecond))

	got := map[string]bool{}
	for _, r := range resolved {
		got[r.Host] = true
	}
	for _, h := range live {
		if !got[h] {
			t.Errorf("%s did not resolve", h)
		}
	}
	if len(resolved) != len(live) {
		t.Errorf("resolved %d hosts, want %d", len(resolved), len(live))
	}
}

func TestResolverFallback(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: never routed, so queries time out.
	if resolversReachable([]string{"udp:192.0.2.1:53"}, "wikipedia.org") {
		t.Fatal("blackholed resolver reported reachable")
	}
	sys := systemResolvers()
	if len(sys) == 0 {
		t.Skip("no /etc/resolv.conf nameservers")
	}
	if !resolversReachable(sys, "wikipedia.org") {
		t.Fatalf("system resolvers %v unreachable", sys)
	}
	t.Logf("fallback resolvers: %v", sys)
}
