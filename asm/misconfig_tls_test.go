package asm

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTLSMisconfigs(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	good := TLSCert{Host: "www.example.com", Port: 443, TLSVersion: "tls13", Cipher: "TLS_AES_128_GCM_SHA256",
		SubjectCN: "www.example.com", NotAfter: now.AddDate(0, 3, 0)}
	certs := []TLSCert{
		good,
		{Host: "old.example.com", Port: 8443, TLSVersion: "tls10", Cipher: "TLS_RSA_WITH_RC4_128_SHA",
			SubjectCN: "old.example.com", NotAfter: now.AddDate(0, 0, -2), Expired: true},
		{Host: "soon.example.com", Port: 443, TLSVersion: "tls12", Cipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			SubjectCN: "soon.example.com", NotAfter: now.AddDate(0, 0, 10)},
		{Host: "dev.example.com", Port: 443, TLSVersion: "tls12", Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			SubjectCN: "localhost", NotAfter: now.AddDate(1, 0, 0), SelfSigned: true, Mismatched: true},
	}
	var got []string
	for _, m := range tlsMisconfigs(certs, now) {
		got = append(got, fmt.Sprintf("%s:%d %s %s: %s", m.Host, m.Port, m.Check, m.Severity, m.Detail))
	}
	want := []string{
		"old.example.com:8443 tls_version medium: negotiates TLS 1.0 at best: it's deprecated and lacks modern protections; support TLS 1.2 or 1.3",
		"old.example.com:8443 tls_cipher high: negotiates the weak cipher TLS_RSA_WITH_RC4_128_SHA",
		"old.example.com:8443 cert_expired high: certificate for old.example.com expired on 2026-11-17",
		"soon.example.com:443 cert_expiring medium: certificate for soon.example.com expires on 2026-11-29",
		"dev.example.com:443 tls_cipher high: negotiates the weak cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"dev.example.com:443 cert_self_signed medium: certificate for localhost is self-signed, so browsers and clients don't trust it",
		"dev.example.com:443 cert_mismatch medium: certificate for localhost doesn't cover dev.example.com",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWeakCipher(t *testing.T) {
	for cipher, want := range map[string]bool{
		"TLS_AES_256_GCM_SHA384":                  false,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    false,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      false,
		"TLS_RSA_WITH_RC4_128_MD5":                true,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     true,
		"TLS_RSA_WITH_NULL_SHA256":                true,
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":       true,
		"TLS_DH_anon_WITH_AES_128_CBC_SHA":        true,
		"TLS_RSA_WITH_DES_CBC_SHA":                true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": false,
	} {
		if got := weakCipher(cipher); got != want {
			t.Errorf("weakCipher(%q) = %v, want %v", cipher, got, want)
		}
	}
}

func TestTLSPortsByHost(t *testing.T) {
	hosts := []resolvedHost{{Host: "a.example.com", IPs: []string{"192.0.2.1"}}, {Host: "b.example.com", IPs: []string{"192.0.2.2"}}}
	scans := []PortScan{{IP: "192.0.2.1", Ports: []OpenPort{
		{Port: 22, Protocol: "tcp", Service: &Service{Name: "ssh"}},
		{Port: 993, Protocol: "tcp", Service: &Service{Name: "imap", TLS: true}},
		{Port: 8443, Protocol: "tcp", Service: &Service{Name: "http", TLS: true}},
	}}}
	pages := []WebPage{
		{Host: "b.example.com", Port: 9443, Scheme: "https"},
		{Host: "b.example.com", Port: 8080, Scheme: "http"},
		{Host: "a.example.com", Port: 8443, Scheme: "https"},
	}
	got := tlsPortsByHost(hosts, scans, pages)
	if want := "map[a.example.com:[993 8443] b.example.com:[9443]]"; fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
