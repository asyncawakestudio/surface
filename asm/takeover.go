package asm

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
)

// takeoverRisk is a subdomain whose CNAME points at a third-party resource
// that may be unclaimed, so someone else could claim it and serve content on
// the subdomain. It is reported as a Misconfiguration with Check "takeover".
type takeoverRisk struct {
	host     string
	cname    string // the target the subdomain points at
	service  string // provider, e.g. "AWS/S3"; empty when unknown
	severity string // "high" when the service's fingerprint matched, else "medium"
	evidence string // what matched, e.g. `https response contains "NoSuchBucket"`
	ref      string // discussion of taking over the service
}

func (r takeoverRisk) misconfig() Misconfiguration {
	detail := fmt.Sprintf("CNAME %s %s", r.cname, r.evidence)
	if r.service != "" {
		detail = fmt.Sprintf("CNAME %s (%s) looks unclaimed: %s", r.cname, r.service, r.evidence)
	}
	return Misconfiguration{
		Host: r.host, Check: "takeover", Severity: r.severity, Detail: detail,
		CNAME: r.cname, Service: r.service, Reference: r.ref,
	}
}

//go:embed data/takeover-fingerprints.json
var takeoverFingerprintsJSON []byte

// takeoverFingerprint is a service from can-i-take-over-xyz known to allow
// takeovers, with how to tell that a resource on it is unclaimed.
type takeoverFingerprint struct {
	service   string
	cnames    []string       // domain suffixes (or IPs) of the service
	nxdomain  bool           // unclaimed resources have no DNS records
	status    int            // unclaimed resources answer with this HTTP status
	body      *regexp.Regexp // unclaimed resources' response body matches this
	reference string
}

var takeoverFingerprints = sync.OnceValue(func() []takeoverFingerprint {
	fps, err := parseTakeoverFingerprints(takeoverFingerprintsJSON)
	if err != nil {
		panic("asm: embedded takeover fingerprints: " + err.Error())
	}
	return fps
})

// parseTakeoverFingerprints keeps the services marked vulnerable that name
// their CNAMEs and how to recognize an unclaimed resource. Services without
// CNAMEs are dropped: matching a generic error page alone is too noisy.
func parseTakeoverFingerprints(data []byte) ([]takeoverFingerprint, error) {
	var raw []struct {
		Service     string   `json:"service"`
		CNAME       []string `json:"cname"`
		Fingerprint string   `json:"fingerprint"`
		NXDomain    bool     `json:"nxdomain"`
		HTTPStatus  *int     `json:"http_status"`
		Vulnerable  bool     `json:"vulnerable"`
		Discussion  string   `json:"discussion"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []takeoverFingerprint
	for _, r := range raw {
		if !r.Vulnerable || len(r.CNAME) == 0 {
			continue
		}
		fp := takeoverFingerprint{service: r.Service, nxdomain: r.NXDomain, reference: r.Discussion}
		for _, c := range r.CNAME {
			fp.cnames = append(fp.cnames, normalizeName(c))
		}
		text := strings.TrimSpace(html.UnescapeString(r.Fingerprint))
		switch {
		case fp.nxdomain:
		case strings.HasPrefix(text, "HTTP_STATUS="):
			fp.status, _ = strconv.Atoi(strings.TrimPrefix(text, "HTTP_STATUS="))
		case r.HTTPStatus != nil && text == "":
			fp.status = *r.HTTPStatus
		case text != "":
			// Fingerprints are mostly literal text, some regular expressions.
			re, err := regexp.Compile(text)
			if err != nil {
				re = regexp.MustCompile(regexp.QuoteMeta(text))
			}
			fp.body = re
		}
		if !fp.nxdomain && fp.status == 0 && fp.body == nil {
			continue
		}
		out = append(out, fp)
	}
	return out, nil
}

// matchTakeoverService returns the fingerprint of the service one of names
// (CNAMEs or IPs) belongs to.
func matchTakeoverService(fps []takeoverFingerprint, names []string) (*takeoverFingerprint, string) {
	for i := range fps {
		for _, n := range names {
			for _, c := range fps[i].cnames {
				if n == c || strings.HasSuffix(n, "."+c) {
					return &fps[i], n
				}
			}
		}
	}
	return nil, ""
}

// takeoverCandidate is a host with a CNAME, as the DNS stage recorded it.
type takeoverCandidate struct {
	host   string
	cnames []string // in the order DNS returned them; the last is the target
	ips    []string
}

// findTakeovers checks every host with a CNAME. A host is at risk when its
// CNAME points at a known service and the service's fingerprint for an
// unclaimed resource matches (no DNS records, an error page or status), or
// when the CNAME target outside the scanned domain does not exist.
//
// It sends HTTP requests only to hosts whose CNAME names a service with an
// error-page fingerprint, and DNS queries only for CNAME targets that didn't
// resolve.
func (s *Scanner) findTakeovers(ctx context.Context, domain string, records []DNSRecord) ([]takeoverRisk, error) {
	candidates := takeoverCandidates(records)
	if len(candidates) == 0 {
		return nil, nil
	}
	dns, err := newDNSClient(s.dnsResolvers(domain), []uint16{miekgdns.TypeA})
	if err != nil {
		return nil, err
	}
	nxdomain := func(name string) bool {
		data, err := dns.QueryOne(name)
		return err == nil && data != nil && data.StatusCode == miekgdns.RcodeToString[miekgdns.RcodeNameError]
	}
	client := takeoverHTTPClient(s.opts.WebTimeout)
	fps := takeoverFingerprints()
	s.opts.Logger.Info("misconfig: checking CNAMEs for takeovers", "hosts", len(candidates))

	risks := make([]*takeoverRisk, len(candidates))
	forEach(ctx, candidates, s.opts.WebConcurrency, func(i int, c takeoverCandidate) {
		target := c.cnames[len(c.cnames)-1]
		dangling := len(c.ips) == 0 && nxdomain(target)
		fp, matched := matchTakeoverService(fps, append(slices.Clone(c.cnames), c.ips...))
		if fp == nil {
			if dangling && !inDomain(target, domain) {
				risks[i] = &takeoverRisk{host: c.host, cname: target, severity: "medium",
					evidence: "does not exist (NXDOMAIN); check whether it can be registered or claimed"}
			}
			return
		}
		risk := &takeoverRisk{host: c.host, cname: matched, service: fp.service, severity: "high", ref: fp.reference}
		switch {
		case fp.nxdomain:
			if !dangling {
				return
			}
			risk.evidence = "target does not exist (NXDOMAIN)"
		case len(c.ips) == 0:
			return // nothing to request
		default:
			evidence, ok := probeTakeover(ctx, client, c.host, fp)
			if !ok {
				return
			}
			risk.evidence = evidence
		}
		risks[i] = risk
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var out []takeoverRisk
	for _, r := range risks {
		if r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

// probeTakeover requests host over HTTPS and HTTP and reports whether a
// response matches the service's fingerprint for an unclaimed resource.
func probeTakeover(ctx context.Context, client *http.Client, host string, fp *takeoverFingerprint) (string, bool) {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			return "", false
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if fp.status != 0 && resp.StatusCode == fp.status {
			return fmt.Sprintf("%s responds with HTTP %d", scheme, resp.StatusCode), true
		}
		if fp.body != nil {
			if m := fp.body.Find(body); m != nil {
				return fmt.Sprintf("%s response contains %q", scheme, truncateBanner(string(m))), true
			}
		}
	}
	return "", false
}

// takeoverHTTPClient doesn't follow redirects, since a fingerprinted status
// such as 301 must be seen as is, and doesn't verify certificates: an
// unclaimed resource usually presents the provider's certificate, not one for
// the subdomain.
func takeoverHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see above
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// takeoverCandidates groups the CNAME and address records of hosts that
// have a CNAME, sorted by host.
func takeoverCandidates(records []DNSRecord) []takeoverCandidate {
	byHost := map[string]*takeoverCandidate{}
	var hosts []string
	for _, r := range records {
		c := byHost[r.Host]
		if c == nil {
			c = &takeoverCandidate{host: r.Host}
			byHost[r.Host] = c
			hosts = append(hosts, r.Host)
		}
		switch r.Type {
		case "CNAME":
			if n := normalizeName(r.Value); !slices.Contains(c.cnames, n) {
				c.cnames = append(c.cnames, n)
			}
		case "A", "AAAA":
			c.ips = append(c.ips, r.Value)
		}
	}
	slices.Sort(hosts)
	var out []takeoverCandidate
	for _, h := range hosts {
		if c := byHost[h]; len(c.cnames) > 0 {
			out = append(out, *c)
		}
	}
	return out
}

// inDomain reports whether name is domain or one of its subdomains.
func inDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
