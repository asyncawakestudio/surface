package asm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	miekgdns "github.com/miekg/dns"
)

// Misconfiguration is a DNS or email security setting that weakens the
// domain: spoofable mail (SPF, DMARC), a zone anyone can download (AXFR), or no
// restriction on who may issue its certificates (CAA).
type Misconfiguration struct {
	Host string `json:"host"`
	// Check is "spf", "dmarc", "zone_transfer" or "caa".
	Check string `json:"check"`
	// Severity is "high", "medium" or "low".
	Severity string `json:"severity"`
	// Detail says what is wrong and, where it helps, what the record says.
	Detail string `json:"detail"`
}

const dnsCheckTimeout = 5 * time.Second

// axfrPort is the nameserver port zone transfers are tried on; tests change it.
var axfrPort = "53"

// checkMisconfigs runs the DNS and email checks on the root domain, plus SPF
// on every subdomain that receives mail (has MX records). DMARC is checked on
// the root only: its policy covers subdomains unless they publish their own.
func (s *Scanner) checkMisconfigs(ctx context.Context, domain string, records []DNSRecord) ([]Misconfiguration, error) {
	q := dnsQuerier{resolvers: plainResolvers(s.dnsResolvers(domain))}
	if len(q.resolvers) == 0 {
		return nil, errors.New("no resolvers")
	}
	s.opts.Logger.Info("misconfig: checking DNS and email settings", "domain", domain)

	var out []Misconfiguration
	add := func(host, check, severity, format string, a ...any) {
		out = append(out, Misconfiguration{Host: host, Check: check, Severity: severity, Detail: fmt.Sprintf(format, a...)})
	}

	mailHosts := map[string]bool{}
	for _, r := range records {
		if r.Type == "MX" {
			mailHosts[r.Host] = true
		}
	}
	rootMX, err := q.lookup(ctx, domain, miekgdns.TypeMX)
	if err != nil {
		return nil, err
	}
	mailHosts[domain] = len(rootMX) > 0 || mailHosts[domain]

	// SPF
	hosts := []string{domain}
	for h := range mailHosts {
		if h != domain {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts[1:])
	for _, h := range hosts {
		txt, err := q.lookup(ctx, h, miekgdns.TypeTXT)
		if err != nil {
			return nil, err
		}
		for _, f := range checkSPF(txtValues(txt), mailHosts[h]) {
			add(h, "spf", f.severity, "%s", f.detail)
		}
	}

	// DMARC
	dmarc, err := q.lookup(ctx, "_dmarc."+domain, miekgdns.TypeTXT)
	if err != nil {
		return nil, err
	}
	for _, f := range checkDMARC(txtValues(dmarc)) {
		add(domain, "dmarc", f.severity, "%s", f.detail)
	}

	// CAA
	caa, err := q.lookup(ctx, domain, miekgdns.TypeCAA)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(caa, func(rr miekgdns.RR) bool { _, ok := rr.(*miekgdns.CAA); return ok }) {
		add(domain, "caa", "low", "no CAA record: any certificate authority may issue certificates for the domain")
	}

	// Zone transfers
	nsRRs, err := q.lookup(ctx, domain, miekgdns.TypeNS)
	if err != nil {
		return nil, err
	}
	var nameservers []string
	for _, rr := range nsRRs {
		if ns, ok := rr.(*miekgdns.NS); ok {
			nameservers = append(nameservers, normalizeName(ns.Ns))
		}
	}
	slices.Sort(nameservers)
	for _, ns := range nameservers {
		if n, ok := zoneTransfer(ctx, domain, net.JoinHostPort(ns, axfrPort)); ok {
			add(domain, "zone_transfer", "high", "nameserver %s allows zone transfers (AXFR): anyone can list all %d records", ns, n)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type finding struct{ severity, detail string }

// checkSPF checks the SPF record among a host's TXT values. receivesMail is
// whether the host has MX records; one without them should still publish
// "v=spf1 -all", or anyone can send mail as it.
func checkSPF(txt []string, receivesMail bool) []finding {
	var spf []string
	for _, t := range txt {
		if f := strings.Fields(strings.ToLower(t)); len(f) > 0 && f[0] == "v=spf1" {
			spf = append(spf, t)
		}
	}
	switch {
	case len(spf) == 0 && receivesMail:
		return []finding{{"medium", "no SPF record: anyone can send mail as this domain"}}
	case len(spf) == 0:
		return []finding{{"low", `no SPF record; if the domain sends no mail, publish "v=spf1 -all" so it can't be spoofed`}}
	case len(spf) > 1:
		return []finding{{"medium", fmt.Sprintf("%d SPF records: receivers treat this as an error and ignore SPF", len(spf))}}
	}
	record := spf[0]
	terms := strings.Fields(strings.ToLower(record))
	all := ""
	for _, t := range terms[1:] {
		if strings.TrimLeft(t, "+-~?") == "all" {
			all = t
		}
	}
	redirect := slices.ContainsFunc(terms, func(t string) bool { return strings.HasPrefix(t, "redirect=") })
	switch {
	case all == "all" || all == "+all":
		return []finding{{"high", fmt.Sprintf("SPF allows any server to send mail (%s): %q", all, record)}}
	case all == "?all":
		return []finding{{"medium", fmt.Sprintf("SPF ends in ?all (neutral), which doesn't reject spoofed mail: %q", record)}}
	case all == "" && !redirect:
		return []finding{{"medium", fmt.Sprintf("SPF has no \"all\" mechanism, so unlisted servers aren't rejected: %q", record)}}
	}
	return nil
}

// checkDMARC checks the TXT values of _dmarc.<domain>.
func checkDMARC(txt []string) []finding {
	var dmarc []string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			dmarc = append(dmarc, t)
		}
	}
	switch {
	case len(dmarc) == 0:
		return []finding{{"medium", "no DMARC record: receivers aren't told to reject mail that fails SPF and DKIM"}}
	case len(dmarc) > 1:
		return []finding{{"medium", fmt.Sprintf("%d DMARC records: receivers ignore DMARC", len(dmarc))}}
	}
	record := dmarc[0]
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	var out []finding
	switch p := tags["p"]; p {
	case "reject", "quarantine":
	case "none":
		out = append(out, finding{"medium", fmt.Sprintf("DMARC policy is p=none, which only monitors and doesn't stop spoofed mail: %q", record)})
	default:
		out = append(out, finding{"medium", fmt.Sprintf("DMARC record has no valid policy (p=): %q", record)})
	}
	if sp := tags["sp"]; sp == "none" && tags["p"] != "none" {
		out = append(out, finding{"low", fmt.Sprintf("DMARC subdomain policy is sp=none, so subdomains can be spoofed: %q", record)})
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil && n < 100 {
			out = append(out, finding{"low", fmt.Sprintf("DMARC applies to only %d%% of failing mail (pct=%d)", n, n)})
		}
	}
	return out
}

// zoneTransfer attempts an AXFR of domain from nameserver (host:port) and
// returns the number of records received if it succeeds.
func zoneTransfer(ctx context.Context, domain, nameserver string) (int, bool) {
	ctx, cancel := context.WithTimeout(ctx, dnsCheckTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", nameserver)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	t := &miekgdns.Transfer{Conn: &miekgdns.Conn{Conn: conn}}
	m := new(miekgdns.Msg)
	m.SetAxfr(miekgdns.Fqdn(domain))
	envelopes, err := t.In(m, nameserver)
	if err != nil {
		return 0, false
	}
	n := 0
	for env := range envelopes {
		if env.Error != nil {
			return 0, false
		}
		n += len(env.RR)
	}
	// A refused transfer can arrive as an empty answer rather than an error.
	return n, n > 0
}

// dnsQuerier sends single queries to the scan's resolvers, trying each in
// turn until one answers.
type dnsQuerier struct {
	resolvers []string // host:port
}

// lookup returns the answer records of type qtype for name. NXDOMAIN and
// empty answers are not errors.
func (q dnsQuerier) lookup(ctx context.Context, name string, qtype uint16) ([]miekgdns.RR, error) {
	m := new(miekgdns.Msg)
	m.SetQuestion(miekgdns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)
	c := &miekgdns.Client{Timeout: dnsTimeout}
	var lastErr error
resolvers:
	for _, r := range q.resolvers {
		for attempt := 0; attempt <= dnsMaxRetries; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			resp, _, err := c.ExchangeContext(ctx, m, r)
			if err == nil && resp.Truncated {
				tcp := &miekgdns.Client{Net: "tcp", Timeout: dnsTimeout}
				resp, _, err = tcp.ExchangeContext(ctx, m, r)
			}
			if err != nil {
				lastErr = err
				continue
			}
			switch resp.Rcode {
			case miekgdns.RcodeSuccess, miekgdns.RcodeNameError:
				return resp.Answer, nil
			}
			lastErr = errors.New(miekgdns.RcodeToString[resp.Rcode])
			continue resolvers // a server error won't change on retry
		}
	}
	return nil, fmt.Errorf("dns %s %s: %w", miekgdns.TypeToString[qtype], name, lastErr)
}

// plainResolvers converts dnsx resolver specs ("udp:1.1.1.1:53", "1.1.1.1")
// to host:port.
func plainResolvers(resolvers []string) []string {
	var out []string
	for _, r := range resolvers {
		r = strings.TrimPrefix(strings.TrimPrefix(r, "udp:"), "tcp:")
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53")
		}
		out = append(out, r)
	}
	return out
}

// txtValues joins each TXT record's strings, as SPF and DMARC require.
func txtValues(rrs []miekgdns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*miekgdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

// MisconfigDiff lists misconfigurations that appeared (Added) or were fixed
// (Removed).
type MisconfigDiff struct {
	// Compared is false unless both scans ran the checks.
	Compared bool `json:"compared"`
	SetDiff[Misconfiguration]
}

func compareMisconfigs(prev, cur *Result) MisconfigDiff {
	d := MisconfigDiff{SetDiff: SetDiff[Misconfiguration]{Added: []Misconfiguration{}, Removed: []Misconfiguration{}}}
	if !prev.ran(StageMisconfig) || !cur.ran(StageMisconfig) {
		return d
	}
	d.Compared = true
	d.SetDiff = setDiff(prev.Misconfigurations, cur.Misconfigurations, func(m Misconfiguration) string {
		return m.Host + "\x00" + m.Check + "\x00" + m.Detail
	})
	return d
}
