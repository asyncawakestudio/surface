package asm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestLookupIPs(t *testing.T) {
	var mu sync.Mutex
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/93.184.215.14/json":
			_, _ = w.Write([]byte(`{"ip":"93.184.215.14","city":"Los Angeles","asn":{"asn":"AS15133","name":"Edgecast"}}`))
		case "/2606:2800:21f:cb07:6820:80da:af6b:8b2c/json":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Rate limit exceeded"))
		case "/1.1.1.1/json":
			_, _ = w.Write([]byte(`<html>not json</html>`))
		case "/8.8.8.8/json":
			_, _ = w.Write([]byte(`["array", "not object"]`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	s := New(Options{IPInfoBaseURL: srv.URL, IPInfoToken: "tok"})
	hosts := []resolvedHost{
		{Host: "a.example.com", IPs: []string{"93.184.215.14", "10.0.0.5", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"}},
		{Host: "b.example.com", IPs: []string{"93.184.215.14", "127.0.0.1", "192.0.2.10", "1.1.1.1", "8.8.8.8"}},
		{Host: "c.example.com", IPs: []string{"fe80::1", "100.64.1.1", "not-an-ip"}},
	}
	got, err := s.lookupIPs(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}

	// Duplicates and private/reserved addresses are never looked up.
	if len(requested) != 4 {
		t.Fatalf("requested %d IPs, want 4: %v", len(requested), requested)
	}
	byIP := map[string]IPInfo{}
	for _, info := range got {
		byIP[info.IP] = info
	}
	if len(byIP) != 4 {
		t.Fatalf("got %d records, want 4: %+v", len(got), got)
	}

	ok := byIP["93.184.215.14"]
	var data map[string]any
	if ok.Error != "" || json.Unmarshal(ok.Data, &data) != nil || data["city"] != "Los Angeles" {
		t.Fatalf("success record = %+v", ok)
	}
	if e := byIP["2606:2800:21f:cb07:6820:80da:af6b:8b2c"].Error; !strings.Contains(e, "HTTP 429") {
		t.Errorf("rate-limited error = %q", e)
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8"} {
		if r := byIP[ip]; r.Error == "" || r.Data != nil {
			t.Errorf("%s: invalid response accepted: %+v", ip, r)
		}
	}
}

func TestPublicIPs(t *testing.T) {
	got := publicIPs([]resolvedHost{{IPs: []string{
		"8.8.8.8", "1.1.1.1", "8.8.8.8", "::ffff:1.1.1.1", // mapped duplicate
		"172.16.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "240.0.0.1",
		"2001:db8::1", "fc00::1", "2606:4700::1111",
	}}})
	want := "1.1.1.1,8.8.8.8,2606:4700::1111"
	if strings.Join(got, ",") != want {
		t.Fatalf("publicIPs = %v, want %s", got, want)
	}
}
