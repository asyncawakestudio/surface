package asm

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// ErrServiceDetectionNeedsPortScan is returned when service detection is
// requested without the port scan it runs on.
var ErrServiceDetectionNeedsPortScan = errors.New("service detection requires the port scan (Options.PortScan)")

// ErrServiceProbesNotFound is returned when service detection is requested but
// no nmap-service-probes file is available.
var ErrServiceProbesNotFound = errors.New("nmap-service-probes not found: install nmap or set Options.ServiceProbesFile")

// maxBannerLen caps the raw banner kept per service.
const maxBannerLen = 256

// Service is what runs on an open port, identified by actively probing it
// with nmap's service probes (via naabu).
//
// Product, Version and CPEs are what vulnerability databases are keyed on, so
// a later stage (e.g. ProjectDiscovery's vulnx) can look services up without
// re-probing. Use Result.Services to get them flattened with their location.
type Service struct {
	// Name is the protocol, e.g. "ssh", "http".
	Name string `json:"name"`
	// Product is the software, e.g. "OpenSSH", "nginx".
	Product string `json:"product,omitempty"`
	// Version is the product version, e.g. "8.9p1".
	Version string `json:"version,omitempty"`
	// ExtraInfo is free-form detail from the probe match, e.g. "Ubuntu Linux; protocol 2.0".
	ExtraInfo string `json:"extra_info,omitempty"`
	// TLS reports whether the service runs over TLS.
	TLS bool `json:"tls,omitempty"`
	// CPEs identify the product as CPE 2.3 formatted strings
	// (cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*), the form NVD and
	// vulnerability tools match on.
	CPEs []string `json:"cpes,omitempty"`
	// Confidence is naabu's match confidence (higher is more certain).
	Confidence int `json:"confidence,omitempty"`
	// Banner is the start of the service's response, up to 256 bytes.
	Banner string `json:"banner,omitempty"`
}

// Identified reports whether the service carries enough detail to look it up
// in a vulnerability database: a CPE, or a product.
func (s Service) Identified() bool {
	return len(s.CPEs) > 0 || s.Product != ""
}

// ServiceTarget is one detected service together with where it was found.
type ServiceTarget struct {
	IP       string   `json:"ip"`
	Hosts    []string `json:"hosts"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Service  Service  `json:"service"`
}

// Services returns every port with a detected service, flattened and in the
// port scan's order (by IP, then port). It is the input for vulnerability
// lookups. It is empty unless the scan ran with Options.ServiceDetection.
func (r *Result) Services() []ServiceTarget {
	var out []ServiceTarget
	for _, ps := range r.PortScans {
		for _, p := range ps.Ports {
			if p.Service == nil {
				continue
			}
			out = append(out, ServiceTarget{
				IP:       ps.IP,
				Hosts:    slices.Clone(ps.Hosts),
				Port:     p.Port,
				Protocol: p.Protocol,
				Service:  *p.Service,
			})
		}
	}
	return out
}

// truncateBanner keeps at most maxBannerLen bytes of banner without splitting
// a UTF-8 sequence.
func truncateBanner(banner string) string {
	if len(banner) <= maxBannerLen {
		return banner
	}
	cut := maxBannerLen
	for cut > 0 && !utf8.RuneStart(banner[cut]) {
		cut--
	}
	return banner[:cut]
}

// normalizeCPEs converts CPEs to CPE 2.3 formatted strings, dropping invalid
// ones and duplicates while keeping order.
func normalizeCPEs(cpes []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cpes {
		n, ok := CPE23(c)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// cpe23Fields is the number of fields after "cpe:2.3:" (part through other).
const cpe23Fields = 11

// CPE23 converts a CPE to a CPE 2.3 formatted string. It accepts CPE 2.2 URIs
// as nmap writes them ("cpe:/a:openbsd:openssh:8.9p1", optionally with a
// trailing "/" or "/a" flag) and CPE 2.3 formatted strings, which it returns
// with missing fields filled with "*". ok is false for anything else, or a CPE
// without a part, vendor and product.
func CPE23(cpe string) (string, bool) {
	cpe = strings.TrimSpace(cpe)
	var fields []string
	switch {
	case strings.HasPrefix(cpe, "cpe:2.3:"):
		fields = splitCPE23(strings.TrimPrefix(cpe, "cpe:2.3:"))
	case strings.HasPrefix(cpe, "cpe:/"):
		rest := strings.TrimPrefix(cpe, "cpe:/")
		// nmap appends "/" and optionally a flag ("/a") after the CPE.
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		for _, f := range strings.Split(rest, ":") {
			if dec, err := url.PathUnescape(f); err == nil {
				f = dec
			}
			fields = append(fields, escapeCPE23(strings.ToLower(f)))
		}
	default:
		return "", false
	}
	if len(fields) < 3 || len(fields) > cpe23Fields {
		return "", false
	}
	switch fields[0] {
	case "a", "o", "h":
	default:
		return "", false
	}
	if fields[1] == "" || fields[1] == "*" || fields[2] == "" || fields[2] == "*" {
		return "", false
	}
	for len(fields) < cpe23Fields {
		fields = append(fields, "*")
	}
	for i, f := range fields {
		if f == "" {
			fields[i] = "*"
		}
	}
	return "cpe:2.3:" + strings.Join(fields, ":"), true
}

// splitCPE23 splits CPE 2.3 fields on ":" not escaped with "\".
func splitCPE23(s string) []string {
	var fields []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			b.WriteByte(s[i])
			i++
			b.WriteByte(s[i])
		case s[i] == ':':
			fields = append(fields, b.String())
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	return append(fields, b.String())
}

// escapeCPE23 escapes a decoded CPE 2.2 value for a CPE 2.3 formatted string:
// letters, digits, "_", "." and "-" stay as they are, everything else is
// quoted with "\".
func escapeCPE23(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}
