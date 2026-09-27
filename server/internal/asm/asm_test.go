package asm

import (
	"context"
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
