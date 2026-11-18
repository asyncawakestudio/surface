package asm

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCPE23(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		// nmap writes CPE 2.2 URIs, with a trailing "/" and optional flag.
		{"cpe:/a:openbsd:openssh:8.9p1/", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", true},
		{"cpe:/a:openbsd:openssh:8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", true},
		{"cpe:/a:apache:http_server:2.4.52/a", "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*", true},
		{"cpe:/o:linux:linux_kernel/", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", true},
		{"cpe:/a:Microsoft:IIS:10.0", "cpe:2.3:a:microsoft:iis:10.0:*:*:*:*:*:*:*", true},
		// Percent-encoded characters are decoded, then escaped for 2.3.
		{"cpe:/a:vendor:prod%2b%2b:1.0", `cpe:2.3:a:vendor:prod\+\+:1.0:*:*:*:*:*:*:*`, true},
		// An empty field becomes "*".
		{"cpe:/a:vendor:product::sp1", "cpe:2.3:a:vendor:product:*:sp1:*:*:*:*:*:*", true},
		// CPE 2.3 input is padded and kept as is.
		{"cpe:2.3:a:nginx:nginx:1.18.0", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", true},
		{`cpe:2.3:a:vendor:prod\:x:1:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:prod\:x:1:*:*:*:*:*:*:*`, true},
		// Invalid.
		{"", "", false},
		{"openssh 8.9", "", false},
		{"cpe:/x:vendor:product", "", false},
		{"cpe:/a:vendor", "", false},
		{"cpe:/a::product", "", false},
		{"cpe:2.3:a:*:product:1", "", false},
	}
	for _, tt := range tests {
		got, ok := CPE23(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("CPE23(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNormalizeCPEs(t *testing.T) {
	got := normalizeCPEs([]string{
		"cpe:/a:openbsd:openssh:8.9p1/",
		"not a cpe",
		"cpe:/a:openbsd:openssh:8.9p1", // duplicate once normalized
		"cpe:/o:linux:linux_kernel/",
	})
	want := []string{
		"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
	}
	if !slices.Equal(got, want) {
		t.Errorf("normalizeCPEs = %q, want %q", got, want)
	}
	if got := normalizeCPEs(nil); got != nil {
		t.Errorf("normalizeCPEs(nil) = %q, want nil", got)
	}
}

func TestTruncateBanner(t *testing.T) {
	if got := truncateBanner("SSH-2.0-OpenSSH_8.9p1"); got != "SSH-2.0-OpenSSH_8.9p1" {
		t.Errorf("short banner changed: %q", got)
	}
	long := strings.Repeat("a", maxBannerLen-1) + "é" + "tail" // "é" straddles the limit
	got := truncateBanner(long)
	if len(got) > maxBannerLen || !strings.HasSuffix(got, "a") {
		t.Errorf("truncateBanner split a rune or kept too much: len=%d suffix=%q", len(got), got[len(got)-3:])
	}
}

func TestServiceIdentified(t *testing.T) {
	if (Service{Name: "http"}).Identified() {
		t.Error("a bare protocol name should not count as identified")
	}
	if !(Service{Name: "ssh", Product: "OpenSSH"}).Identified() {
		t.Error("a product should count as identified")
	}
	if !(Service{Name: "ssh", CPEs: []string{"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"}}).Identified() {
		t.Error("a CPE should count as identified")
	}
}

func TestResultServices(t *testing.T) {
	ssh := &Service{Name: "ssh", Product: "OpenSSH", Version: "8.9p1"}
	https := &Service{Name: "http", Product: "nginx", TLS: true}
	r := &Result{PortScans: []PortScan{
		{IP: "192.0.2.1", Hosts: []string{"a.example.com", "b.example.com"}, Ports: []OpenPort{
			{Port: 22, Protocol: "tcp", Service: ssh},
			{Port: 8080, Protocol: "tcp"}, // open, service not identified
		}},
		{IP: "192.0.2.2", Hosts: []string{"c.example.com"}, Ports: []OpenPort{
			{Port: 443, Protocol: "tcp", Service: https},
		}},
	}}

	got := r.Services()
	if len(got) != 2 {
		t.Fatalf("Services() = %+v, want 2 entries", got)
	}
	if got[0].IP != "192.0.2.1" || got[0].Port != 22 || got[0].Service.Product != "OpenSSH" ||
		strings.Join(got[0].Hosts, ",") != "a.example.com,b.example.com" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].IP != "192.0.2.2" || got[1].Port != 443 || !got[1].Service.TLS {
		t.Errorf("second = %+v", got[1])
	}

	// The result is a copy: changing it must not change the scan.
	got[0].Hosts[0] = "changed"
	if r.PortScans[0].Hosts[0] != "a.example.com" {
		t.Error("Services() shares the Hosts slice with the result")
	}

	if got := (&Result{}).Services(); got != nil {
		t.Errorf("Services() without a port scan = %+v, want nil", got)
	}
}

func TestRunServiceDetectionNeedsPortScan(t *testing.T) {
	_, err := New(Options{ServiceDetection: true}).Run(t.Context(), Target{Domain: "example.com"}, nil)
	if !errors.Is(err, ErrServiceDetectionNeedsPortScan) {
		t.Fatalf("err = %v, want ErrServiceDetectionNeedsPortScan", err)
	}
}
