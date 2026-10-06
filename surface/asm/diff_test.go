package asm

import (
	"encoding/json"
	"testing"
)

func TestCompare(t *testing.T) {
	prev := &Result{
		Subdomains: []Subdomain{{Host: "a.example.com"}, {Host: "old.example.com"}},
		DNSRecords: []DNSRecord{
			{Host: "a.example.com", Type: "A", Value: "192.0.2.1"},
			{Host: "old.example.com", Type: "A", Value: "192.0.2.9"},
		},
		TLSCerts: []TLSCert{
			{Host: "a.example.com", Port: 443, FingerprintSHA256: "aaa"},
			{Host: "old.example.com", Port: 443, FingerprintSHA256: "ooo"},
			{Host: "same.example.com", Port: 443, FingerprintSHA256: "sss"},
		},
	}
	cur := &Result{
		// Source changes alone are not a change.
		Subdomains: []Subdomain{{Host: "a.example.com", Sources: []string{"crtsh"}}, {Host: "new.example.com"}},
		DNSRecords: []DNSRecord{
			{Host: "a.example.com", Type: "A", Value: "192.0.2.2"},
			{Host: "new.example.com", Type: "CNAME", Value: "x.cdn.net"},
		},
		TLSCerts: []TLSCert{
			{Host: "a.example.com", Port: 443, FingerprintSHA256: "bbb"},
			{Host: "new.example.com", Port: 443, FingerprintSHA256: "nnn"},
			{Host: "same.example.com", Port: 443, FingerprintSHA256: "sss"},
		},
	}

	d := Compare(prev, cur)

	if got := hosts(d.Subdomains.Added); got != "new.example.com" {
		t.Errorf("subdomains added = %q", got)
	}
	if got := hosts(d.Subdomains.Removed); got != "old.example.com" {
		t.Errorf("subdomains removed = %q", got)
	}
	if len(d.DNSRecords.Added) != 2 || len(d.DNSRecords.Removed) != 2 {
		t.Errorf("dns added/removed = %d/%d, want 2/2", len(d.DNSRecords.Added), len(d.DNSRecords.Removed))
	}
	if len(d.TLSCerts.Added) != 1 || d.TLSCerts.Added[0].Host != "new.example.com" {
		t.Errorf("certs added = %+v", d.TLSCerts.Added)
	}
	if len(d.TLSCerts.Removed) != 1 || d.TLSCerts.Removed[0].Host != "old.example.com" {
		t.Errorf("certs removed = %+v", d.TLSCerts.Removed)
	}
	if len(d.TLSCerts.Changed) != 1 || d.TLSCerts.Changed[0].Before.FingerprintSHA256 != "aaa" ||
		d.TLSCerts.Changed[0].After.FingerprintSHA256 != "bbb" {
		t.Errorf("certs changed = %+v", d.TLSCerts.Changed)
	}
	if d.Empty() {
		t.Error("Empty() = true")
	}
}

func TestCompareIdentical(t *testing.T) {
	r := &Result{
		Subdomains: []Subdomain{{Host: "a.example.com"}},
		DNSRecords: []DNSRecord{{Host: "a.example.com", Type: "A", Value: "192.0.2.1"}},
		TLSCerts:   []TLSCert{{Host: "a.example.com", Port: 443, FingerprintSHA256: "aaa"}},
	}
	d := Compare(r, r)
	if !d.Empty() {
		t.Fatalf("diff of identical results not empty: %+v", d)
	}
	// Empty lists, not nil, so the JSON is [] rather than null.
	if d.Subdomains.Added == nil || d.TLSCerts.Changed == nil {
		t.Fatal("nil slices in diff")
	}
}

func hosts(s []Subdomain) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v.Host
	}
	return out
}

func TestCompareNoLongerReported(t *testing.T) {
	prev := &Result{Subdomains: []Subdomain{
		{Host: "a.example.com"},
		{Host: "gone.example.com"},
		{Host: "old.example.com", CarriedOver: true},
	}}
	cur := &Result{Subdomains: []Subdomain{
		{Host: "a.example.com"},
		{Host: "gone.example.com", CarriedOver: true},
		{Host: "old.example.com", CarriedOver: true}, // already carried over last time
	}}
	d := Compare(prev, cur)
	if got := hosts(d.Subdomains.NoLongerReported); got != "gone.example.com" {
		t.Fatalf("no longer reported = %q, want gone.example.com", got)
	}
	if len(d.Subdomains.Removed) != 0 || d.Empty() {
		t.Fatalf("diff = %+v", d.Subdomains)
	}
}

func TestCompareIPInfo(t *testing.T) {
	pub := []DNSRecord{{Host: "a.example.com", Type: "A", Value: "93.184.215.14"}}
	prev := &Result{DNSRecords: pub, IPInfo: []IPInfo{
		{IP: "93.184.215.14", Data: json.RawMessage(`{"ip":"93.184.215.14","org":"AS15133 Edgecast","asn":{"asn":"AS15133"},"city":"LA","readme":"x"}`)},
		{IP: "1.1.1.1", Data: json.RawMessage(`{"org":"AS13335 Cloudflare"}`)},
		{IP: "8.8.8.8", Error: "ipinfo: HTTP 429"},
		{IP: "9.9.9.9", Data: json.RawMessage(`{"org":"AS19281 Quad9","anycast":true}`)},
	}}
	cur := &Result{IPInfo: []IPInfo{
		// Owner moved; readme differs but is ignored; city unchanged.
		{IP: "93.184.215.14", Data: json.RawMessage(`{"ip":"93.184.215.14","org":"AS13335 Cloudflare","asn":{"asn":"AS13335"},"city":"LA","readme":"y"}`)},
		{IP: "8.8.8.8", Data: json.RawMessage(`{"org":"AS15169 Google"}`)}, // was a failed lookup: not a change
		{IP: "9.9.9.9", Data: json.RawMessage(`{"org":"AS19281 Quad9","anycast":true}`)},
		{IP: "2606:4700::1111", Data: json.RawMessage(`{"org":"AS13335 Cloudflare"}`)},
	}}

	d := Compare(prev, cur).IPInfo
	if !d.Compared {
		t.Fatal("Compared = false")
	}
	if len(d.Added) != 1 || d.Added[0].IP != "2606:4700::1111" || len(d.Removed) != 1 || d.Removed[0].IP != "1.1.1.1" {
		t.Fatalf("added/removed = %+v / %+v", d.Added, d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].IP != "93.184.215.14" {
		t.Fatalf("changed = %+v", d.Changed)
	}
	got := d.Changed[0].Fields
	want := []FieldChange{
		{Field: "asn.asn", Before: "AS15133", After: "AS13335"},
		{Field: "org", Before: "AS15133 Edgecast", After: "AS13335 Cloudflare"},
	}
	if len(got) != len(want) {
		t.Fatalf("fields = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCompareIPInfoWithoutBaseline(t *testing.T) {
	// The previous scan resolved public IPs but has no ipinfo data: it ran
	// before IP lookups existed, so every IP would wrongly look new.
	dns := []DNSRecord{{Host: "a.example.com", Type: "A", Value: "93.184.215.14"}}
	prev := &Result{DNSRecords: dns}
	cur := &Result{DNSRecords: dns, IPInfo: []IPInfo{{IP: "93.184.215.14", Data: json.RawMessage(`{}`)}}}
	d := Compare(prev, cur)
	if d.IPInfo.Compared || len(d.IPInfo.Added) != 0 || !d.Empty() {
		t.Fatalf("diff = %+v", d.IPInfo)
	}

	// A previous scan with no public IPs is a real baseline.
	d = Compare(&Result{DNSRecords: []DNSRecord{{Host: "a.example.com", Type: "A", Value: "10.0.0.1"}}}, cur)
	if !d.IPInfo.Compared || len(d.IPInfo.Added) != 1 {
		t.Fatalf("diff = %+v", d.IPInfo)
	}
}

func TestFlattenJSON(t *testing.T) {
	got := flattenJSON(json.RawMessage(`{"a":{"b":1.50,"c":null},"d":[1,"x"],"e":true,"f":12345678901234567890}`))
	want := map[string]string{"a.b": "1.50", "a.c": "", "d": `[1,"x"]`, "e": "true", "f": "12345678901234567890"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
