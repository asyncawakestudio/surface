package asm

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// certExpiryWarning is how far ahead an expiring certificate is flagged.
const certExpiryWarning = 30 * 24 * time.Hour

// weakCipherParts mark cipher suites that are broken or offer no real
// protection: RC4, DES/3DES, NULL encryption, export grade, anonymous key
// exchange and MD5 MACs.
var weakCipherParts = []string{"_RC4_", "_DES_", "_3DES_", "_DES40_", "_NULL_", "_EXPORT", "_ANON_", "_MD5"}

// tlsMisconfigs checks each endpoint's negotiated TLS version and cipher and
// its certificate. now is when the scan ran.
func tlsMisconfigs(certs []TLSCert, now time.Time) []Misconfiguration {
	var out []Misconfiguration
	for _, c := range certs {
		add := func(check, severity, format string, a ...any) {
			out = append(out, Misconfiguration{Host: c.Host, Port: c.Port, Check: check, Severity: severity, Detail: fmt.Sprintf(format, a...)})
		}
		switch c.TLSVersion {
		case "ssl30", "tls10", "tls11":
			add("tls_version", "medium", "negotiates %s at best: it's deprecated and lacks modern protections; support TLS 1.2 or 1.3", tlsVersionName(c.TLSVersion))
		}
		if weakCipher(c.Cipher) {
			add("tls_cipher", "high", "negotiates the weak cipher %s", c.Cipher)
		}
		switch {
		case c.Expired || (!c.NotAfter.IsZero() && now.After(c.NotAfter)):
			add("cert_expired", "high", "certificate for %s expired on %s", c.SubjectCN, c.NotAfter.Format(time.DateOnly))
		case !c.NotAfter.IsZero() && c.NotAfter.Sub(now) < certExpiryWarning:
			add("cert_expiring", "medium", "certificate for %s expires on %s", c.SubjectCN, c.NotAfter.Format(time.DateOnly))
		}
		if c.SelfSigned {
			add("cert_self_signed", "medium", "certificate for %s is self-signed, so browsers and clients don't trust it", c.SubjectCN)
		}
		if c.Mismatched {
			add("cert_mismatch", "medium", "certificate for %s doesn't cover %s", c.SubjectCN, c.Host)
		}
	}
	return out
}

func weakCipher(cipher string) bool {
	c := "_" + strings.ToUpper(cipher) + "_"
	return slices.ContainsFunc(weakCipherParts, func(p string) bool { return strings.Contains(c, p) })
}

func tlsVersionName(v string) string {
	switch v {
	case "ssl30":
		return "SSL 3.0"
	case "tls10":
		return "TLS 1.0"
	case "tls11":
		return "TLS 1.1"
	}
	return v
}

// sortMisconfigs orders findings most severe first, keeping the check order
// within a severity.
func sortMisconfigs(m []Misconfiguration) {
	slices.SortStableFunc(m, func(a, b Misconfiguration) int {
		return severityRank[b.Severity] - severityRank[a.Severity]
	})
}

// tlsPortsByHost lists, per host, the ports beyond Options.TLSPorts where TLS
// was seen: HTTPS pages from the web stage, and open ports where service
// detection found TLS on one of the host's IPs.
func tlsPortsByHost(hosts []resolvedHost, scans []PortScan, pages []WebPage) map[string][]int {
	tlsByIP := map[string][]int{}
	for _, ps := range scans {
		for _, p := range ps.Ports {
			if p.Protocol == "tcp" && p.Service != nil && p.Service.TLS {
				tlsByIP[ps.IP] = append(tlsByIP[ps.IP], p.Port)
			}
		}
	}
	out := map[string][]int{}
	add := func(host string, port int) {
		if !slices.Contains(out[host], port) {
			out[host] = append(out[host], port)
		}
	}
	for _, h := range hosts {
		for _, ip := range h.IPs {
			for _, p := range tlsByIP[ip] {
				add(h.Host, p)
			}
		}
	}
	for _, p := range pages {
		if p.Scheme == "https" {
			add(p.Host, p.Port)
		}
	}
	for h := range out {
		slices.Sort(out[h])
	}
	return out
}
