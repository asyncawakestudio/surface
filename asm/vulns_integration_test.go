//go:build integration

package asm

import (
	"os"
	"slices"
	"testing"
)

// TestLookupVulnsLive queries NVD and vulnx for OpenSSH 8.9p1, which is
// affected by, among others, CVE-2023-38408 (on CISA's KEV list).
func TestLookupVulnsLive(t *testing.T) {
	s := New(Options{NVDAPIKey: os.Getenv("NVD_API_KEY"), PDCPAPIKey: os.Getenv("PDCP_API_KEY")})
	svc := ServiceTarget{
		IP: "192.0.2.1", Hosts: []string{"ssh.example.com"}, Port: 22, Protocol: "tcp",
		Service: Service{Name: "ssh", Product: "OpenSSH", Version: "8.9p1", CPEs: []string{
			"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
			"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", // no version: not looked up
		}},
	}
	got, err := s.lookupVulns(t.Context(), []ServiceTarget{svc})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CPE != "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*" {
		t.Fatalf("lookupVulns = %+v, want one entry for the OpenSSH CPE", got)
	}
	vulns := got[0].Vulnerabilities
	i := slices.IndexFunc(vulns, func(v Vulnerability) bool { return v.ID == "CVE-2023-38408" })
	if i < 0 {
		t.Fatalf("CVE-2023-38408 missing from %d CVEs", len(vulns))
	}
	v := vulns[i]
	if v.Severity != "critical" || !v.Enriched || !v.KEV {
		t.Errorf("CVE-2023-38408 = %+v, want critical, enriched, KEV", v)
	}
	if !vulns[0].KEV {
		t.Errorf("first CVE %s is not KEV; known-exploited CVEs should sort first", vulns[0].ID)
	}
	t.Logf("%d CVEs; first: %+v", len(vulns), vulns[0])
}
