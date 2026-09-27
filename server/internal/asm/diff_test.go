package asm

import "testing"

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
