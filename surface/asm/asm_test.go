package asm

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "example.com", want: "example.com"},
		{in: "  Example.COM. ", want: "example.com"},
		{in: "https://www.example.com/path?q=1", want: "www.example.com"},
		{in: "example.com:8443", want: "example.com"},
		{in: "*.example.co.uk", want: "example.co.uk"},
		{in: "localhost", wantErr: true},
		{in: "", wantErr: true},
		{in: "exa mple.com", wantErr: true},
		{in: "-bad.example.com", wantErr: true},
		{in: "1.2.3.4", wantErr: true},
		{in: "example.com; rm -rf /", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeDomain(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeDomain(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestForEachVisitsAllItems(t *testing.T) {
	items := make([]int, 100)
	var calls atomic.Int32
	seen := make([]bool, len(items))
	forEach(context.Background(), items, 8, func(i int, _ int) {
		calls.Add(1)
		seen[i] = true
	})
	if calls.Load() != int32(len(items)) {
		t.Fatalf("calls = %d, want %d", calls.Load(), len(items))
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("item %d not visited", i)
		}
	}
}

func TestForEachStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	forEach(ctx, make([]int, 100), 1, func(int, int) { calls.Add(1) })
	if calls.Load() != 0 {
		t.Fatalf("calls = %d after cancel, want 0", calls.Load())
	}
}

func TestMergeSubdomains(t *testing.T) {
	found := []Subdomain{
		{Host: "www.example.com", Sources: []string{"crtsh"}},
		{Host: "api.example.com", Sources: []string{"anubis"}},
	}
	known := []Subdomain{
		{Host: "www.example.com", Sources: []string{"virustotal"}}, // found again: keep this scan's sources
		{Host: "old.example.com", Sources: []string{"hackertarget"}},
		{Host: "example.com", Sources: []string{"input"}},
		{Host: "evil.com"},        // not under the domain
		{Host: "notexample.com"},  // suffix but not a subdomain
		{Host: "old.example.com"}, // duplicate
	}
	got := mergeSubdomains("example.com", found, known)

	want := []Subdomain{
		{Host: "api.example.com", Sources: []string{"anubis"}},
		{Host: "example.com", Sources: []string{"input"}, CarriedOver: true},
		{Host: "old.example.com", Sources: []string{"hackertarget"}, CarriedOver: true},
		{Host: "www.example.com", Sources: []string{"crtsh"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d subdomains, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Host != want[i].Host || got[i].CarriedOver != want[i].CarriedOver ||
			strings.Join(got[i].Sources, ",") != strings.Join(want[i].Sources, ",") {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Mutating the result must not touch the caller's slices.
	got[2].Sources[0] = "x"
	if known[1].Sources[0] != "hackertarget" {
		t.Fatal("merge aliased the known subdomain's sources")
	}
}
