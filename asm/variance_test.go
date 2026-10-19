//go:build integration

package asm

import (
	"context"
	"testing"
)

func TestSubfinderVariance(t *testing.T) {
	s := New(Options{SubfinderMaxTime: 0})
	for run := 1; run <= 3; run++ {
		subs, err := s.enumerateSubdomains(context.Background(), "acquisory.com")
		if err != nil {
			t.Fatal(err)
		}
		hosts := make([]string, len(subs))
		for i, sd := range subs {
			hosts[i] = sd.Host
		}
		t.Logf("run %d: %d subs: %v", run, len(subs), hosts)
	}
}
