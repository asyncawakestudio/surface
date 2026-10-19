//go:build integration

package asm

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Live ipinfo.io lookup; uses IPINFO_TOKEN if set.
func TestIPInfoLive(t *testing.T) {
	s := New(Options{IPInfoToken: os.Getenv("IPINFO_TOKEN")})
	got, err := s.lookupIPs(context.Background(), []resolvedHost{{Host: "dns.google", IPs: []string{"8.8.8.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Error != "" {
		t.Fatalf("lookup = %+v", got)
	}
	var data map[string]any
	if err := json.Unmarshal(got[0].Data, &data); err != nil || data["ip"] != "8.8.8.8" {
		t.Fatalf("data = %s", got[0].Data)
	}
	t.Logf("%s", got[0].Data)
}
