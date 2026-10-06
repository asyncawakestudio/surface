// Package asm implements the attack surface discovery pipeline.
//
// A scan runs a sequence of stages against a root domain:
//
//	subdomains (subfinder) -> dns (dnsx) -> ipdr (ipinfo.io) -> ports (naabu) -> certs (tlsx)
//
// Port scanning and service enumeration will slot in after the DNS stage,
// since they need resolved hosts as input.
package asm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Stage identifies a step of the scan pipeline.
type Stage string

const (
	StageSubdomains Stage = "subdomains"
	StageDNS        Stage = "dns"
	StageIPDR       Stage = "ipdr"
	StagePorts      Stage = "ports"
	StageCerts      Stage = "certs"
)

// ProgressFunc is called when the scan enters a new stage.
type ProgressFunc func(Stage)

// Subdomain is a hostname discovered by passive enumeration.
type Subdomain struct {
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
	// CarriedOver is true when no source reported the host in this scan and
	// it was kept from an earlier one (subdomains are append-only).
	CarriedOver bool `json:"carried_over"`
}

// Target is what a scan runs against.
type Target struct {
	Domain string
	// KnownSubdomains are subdomains found by earlier scans of Domain. They
	// are kept in the result even if passive sources no longer report them,
	// and still go through DNS and TLS so their current state is captured.
	KnownSubdomains []Subdomain
}

// DNSRecord is a single resolved record for a host.
type DNSRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// TLSCert is the leaf certificate presented by a host.
type TLSCert struct {
	Host              string    `json:"host"`
	IP                string    `json:"ip"`
	Port              int       `json:"port"`
	TLSVersion        string    `json:"tls_version"`
	Cipher            string    `json:"cipher"`
	SubjectCN         string    `json:"subject_cn"`
	SubjectOrg        []string  `json:"subject_org"`
	SANs              []string  `json:"sans"`
	IssuerCN          string    `json:"issuer_cn"`
	IssuerOrg         []string  `json:"issuer_org"`
	Serial            string    `json:"serial"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	Expired           bool      `json:"expired"`
	SelfSigned        bool      `json:"self_signed"`
	Mismatched        bool      `json:"mismatched"`
	Wildcard          bool      `json:"wildcard"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

// Result is everything discovered for a domain.
type Result struct {
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
	DNSRecords []DNSRecord `json:"dns_records"`
	TLSCerts   []TLSCert   `json:"tls_certs"`
	IPInfo     []IPInfo    `json:"ip_info"`
	PortScans  []PortScan  `json:"port_scans"`
}

// Options tunes the scanner. Zero values fall back to defaults.
type Options struct {
	// SubfinderProviderConfig is the path to a subfinder provider-config.yaml
	// holding API keys for passive sources. Optional.
	SubfinderProviderConfig string
	// SubfinderMaxTime caps passive enumeration time.
	SubfinderMaxTime time.Duration
	// Resolvers overrides the DNS resolvers used by dnsx ("udp:1.1.1.1:53").
	// When empty, dnsx's public resolvers are used, falling back to the
	// system resolver if they are unreachable.
	Resolvers []string
	// DNSConcurrency is the number of hosts resolved in parallel.
	DNSConcurrency int
	// TLSConcurrency is the number of hosts probed for TLS in parallel.
	TLSConcurrency int
	// TLSPorts are the ports probed for certificates.
	TLSPorts []int
	// TLSTimeout is the per-connection timeout.
	TLSTimeout time.Duration
	// IPInfoToken authenticates ipinfo.io lookups. Optional: without it the
	// free tier's lower rate limits apply.
	IPInfoToken string
	// IPInfoBaseURL defaults to https://ipinfo.io.
	IPInfoBaseURL string
	// IPInfoConcurrency is the number of ipinfo lookups in flight.
	IPInfoConcurrency int
	// HTTPClient is used for ipinfo lookups.
	HTTPClient *http.Client
	// PortScan enables the naabu port-scanning stage. A full SYN scan of all
	// TCP ports is heavy and needs raw-socket privileges, so it is opt-in.
	PortScan bool
	// SkipIPDR disables the IPDR stage (IP data records via ipinfo.io).
	SkipIPDR bool
	// SkipCerts disables the certificate stage (TLS inspection via tlsx).
	SkipCerts bool
	// PortScanType selects the naabu scan mode: "syn" (half-open, needs raw
	// sockets and a routable interface) or "connect" (full TCP connect, works
	// through NAT such as a Docker bridge / WSL2). Defaults to "syn".
	PortScanType string
	// PortScanPorts is the naabu port spec; "-" means all 65535 TCP ports.
	PortScanPorts string
	// PortScanRate is packets per second.
	PortScanRate int
	// PortScanRetries is the per-port retry count.
	PortScanRetries int
	// PortScanThreads is naabu's worker count.
	PortScanThreads int
	// PortScanTimeout is the per-port timeout.
	PortScanTimeout time.Duration
	// Logger receives stage diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.SubfinderMaxTime <= 0 {
		o.SubfinderMaxTime = 10 * time.Minute
	}
	if o.DNSConcurrency <= 0 {
		o.DNSConcurrency = 100
	}
	if o.TLSConcurrency <= 0 {
		o.TLSConcurrency = 25
	}
	if len(o.TLSPorts) == 0 {
		o.TLSPorts = []int{443}
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = 5 * time.Second
	}
	if o.IPInfoBaseURL == "" {
		o.IPInfoBaseURL = "https://ipinfo.io"
	}
	if o.IPInfoConcurrency <= 0 {
		o.IPInfoConcurrency = 8
	}
	if o.PortScanType == "" {
		o.PortScanType = "syn"
	}
	if o.PortScanPorts == "" {
		o.PortScanPorts = "-" // all 65535 TCP ports
	}
	if o.PortScanRate <= 0 {
		o.PortScanRate = 5000 // packets/sec; SYN scan is send-bound, so this sets the pace
	}
	if o.PortScanRetries <= 0 {
		o.PortScanRetries = 2 // each retry resends unanswered ports, i.e. another full pass
	}
	if o.PortScanThreads <= 0 {
		o.PortScanThreads = 25
	}
	if o.PortScanTimeout <= 0 {
		o.PortScanTimeout = time.Second
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Scanner runs the discovery pipeline. It is safe for concurrent use.
type Scanner struct {
	opts Options
}

// New returns a Scanner configured with opts.
func New(opts Options) *Scanner {
	return &Scanner{opts: opts.withDefaults()}
}

// Run executes every stage against the target and returns the combined
// result. progress may be nil.
func (s *Scanner) Run(ctx context.Context, target Target, progress ProgressFunc) (*Result, error) {
	domain, err := NormalizeDomain(target.Domain)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = func(Stage) {}
	}

	res := &Result{Domain: domain}

	progress(StageSubdomains)
	found, err := s.enumerateSubdomains(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("subdomain enumeration: %w", err)
	}
	res.Subdomains = mergeSubdomains(domain, found, target.KnownSubdomains)

	hosts := make([]string, len(res.Subdomains))
	for i, sd := range res.Subdomains {
		hosts[i] = sd.Host
	}

	progress(StageDNS)
	records, resolved, err := s.resolve(ctx, domain, hosts)
	if err != nil {
		return nil, fmt.Errorf("dns resolution: %w", err)
	}
	res.DNSRecords = records

	if !s.opts.SkipIPDR {
		progress(StageIPDR)
		res.IPInfo, err = s.lookupIPs(ctx, resolved)
		if err != nil {
			return nil, fmt.Errorf("ip lookup: %w", err)
		}
	}

	if s.opts.PortScan {
		progress(StagePorts)
		res.PortScans, err = s.scanPorts(ctx, resolved)
		if err != nil {
			return nil, fmt.Errorf("port scanning: %w", err)
		}
	}

	// TODO: service enumeration goes here, and discovered open ports can feed
	// the TLS stage instead of the static TLSPorts list.

	if !s.opts.SkipCerts {
		progress(StageCerts)
		res.TLSCerts, err = s.grabCerts(ctx, resolved)
		if err != nil {
			return nil, fmt.Errorf("tls probing: %w", err)
		}
	}

	return res, nil
}

// mergeSubdomains adds known subdomains that weren't found again, marked as
// carried over with the sources that reported them before. Known hosts
// outside domain are dropped. The result is sorted by host.
func mergeSubdomains(domain string, found, known []Subdomain) []Subdomain {
	out := slices.Clone(found)
	seen := make(map[string]bool, len(found))
	for _, sd := range found {
		seen[sd.Host] = true
	}
	for _, sd := range known {
		if seen[sd.Host] || (sd.Host != domain && !strings.HasSuffix(sd.Host, "."+domain)) {
			continue
		}
		seen[sd.Host] = true
		out = append(out, Subdomain{Host: sd.Host, Sources: slices.Clone(sd.Sources), CarriedOver: true})
	}
	slices.SortFunc(out, func(a, b Subdomain) int { return strings.Compare(a.Host, b.Host) })
	return out
}

var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ErrInvalidDomain is returned for input that is not a registrable hostname.
var ErrInvalidDomain = errors.New("invalid domain")

// NormalizeDomain accepts a bare domain or a URL and returns the lowercased
// hostname, e.g. "https://Example.com/path" -> "example.com".
func NormalizeDomain(input string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", ErrInvalidDomain
		}
		s = u.Hostname()
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if len(s) > 253 || !domainRe.MatchString(s) {
		return "", ErrInvalidDomain
	}
	return s, nil
}
