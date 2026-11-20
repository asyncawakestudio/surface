package asm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	miekgdns "github.com/miekg/dns"
)

// ZoneTransfer is a nameserver that hands the domain's whole zone to anyone
// who asks (AXFR).
type ZoneTransfer struct {
	Nameserver string `json:"nameserver"`
	// Records is the number of records the transfer returned.
	Records int `json:"records"`
}

const dnsCheckTimeout = 5 * time.Second

// axfrPort is the nameserver port zone transfers are tried on; tests change it.
var axfrPort = "53"

// dkimSelectors are DKIM selector names tried on each mail domain
// (<selector>._domainkey.<domain>): DKIM keys can't be listed, so these are
// the defaults of common mail providers (Microsoft 365, Google Workspace,
// Mailchimp/Mandrill, SendGrid, Zoho, Proton, Fastmail, iCloud...).
var dkimSelectors = []string{
	"default", "dkim", "mail", "smtp", "selector1", "selector2", "google",
	"k1", "k2", "k3", "mandrill", "s1", "s2", "zoho", "zmail",
	"protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "sig1",
	"mailjet", "cm", "everlytickey1", "everlytickey2", "mxvault",
}

// maxSPFIncludes caps how many domains named by SPF include: and redirect=
// are looked up. SPF itself allows at most 10 DNS lookups.
const maxSPFIncludes = 20

// lookupDomainRecords queries what the per-host DNS queries don't cover and
// returns it as more DNS records, plus the domain's zone transfers:
//
//   - the root domain's MX records, which decide whether it receives mail;
//   - for each mail domain (the root and every host with MX records): the
//     root's TXT records (SPF) when the host queries missed them, and the TXT
//     records of _dmarc, _mta-sts (MTA-STS), _smtp._tls (TLS-RPT),
//     default._bimi (BIMI) and common DKIM selectors (<selector>._domainkey);
//   - TLSA records of each mail server (_25._tcp.<mx>, DANE);
//   - the SPF records of domains SPF includes or redirects to, recursively;
//   - a zone transfer (AXFR) from each of the domain's nameservers.
//
// A domain with no MX records gets none of the email lookups.
//
// Names that don't exist are skipped, as are lookups that fail.
func (s *Scanner) lookupDomainRecords(ctx context.Context, domain string, records []DNSRecord) ([]DNSRecord, []ZoneTransfer, error) {
	q := dnsQuerier{resolvers: plainResolvers(s.dnsResolvers(domain))}
	if len(q.resolvers) == 0 {
		return nil, nil, errors.New("no resolvers")
	}

	have := map[string]bool{}
	var out []DNSRecord
	add := func(r DNSRecord) {
		key := r.Host + "\x00" + r.Type + "\x00" + r.Value
		if !have[key] {
			have[key] = true
			out = append(out, r)
		}
	}
	for _, r := range records {
		have[r.Host+"\x00"+r.Type+"\x00"+r.Value] = true
	}

	type query struct {
		name  string
		qtype uint16
	}
	// run sends the queries concurrently and adds their answers in order.
	failed := 0
	run := func(queries []query) {
		answers := make([][]DNSRecord, len(queries))
		errs := make([]bool, len(queries))
		forEach(ctx, queries, s.opts.DNSConcurrency, func(i int, qu query) {
			rrs, err := q.lookup(ctx, qu.name, qu.qtype)
			errs[i] = err != nil
			answers[i] = rrValues(qu.name, qu.qtype, rrs)
		})
		for i, a := range answers {
			if errs[i] {
				failed++
			}
			for _, r := range a {
				add(r)
			}
		}
	}

	// Mail domains are those with MX records: every host the host queries
	// found them for, and the root, asked directly since passive sources
	// don't always list it. Only they get the email lookups.
	run([]query{{domain, miekgdns.TypeMX}})
	var mailDomains []string
	for _, r := range append(slices.Clone(records), out...) {
		if r.Type == "MX" && !slices.Contains(mailDomains, r.Host) {
			mailDomains = append(mailDomains, r.Host)
		}
	}
	// The root first, then the other hosts in order.
	slices.SortFunc(mailDomains, func(a, b string) int {
		switch {
		case a == domain:
			return -1
		case b == domain:
			return 1
		}
		return strings.Compare(a, b)
	})
	var queries []query
	if slices.Contains(mailDomains, domain) {
		queries = append(queries, query{domain, miekgdns.TypeTXT}) // SPF
	}
	for _, d := range mailDomains {
		for _, prefix := range []string{"_dmarc.", "_mta-sts.", "_smtp._tls.", "default._bimi."} {
			queries = append(queries, query{prefix + d, miekgdns.TypeTXT})
		}
		for _, sel := range dkimSelectors {
			queries = append(queries, query{sel + "._domainkey." + d, miekgdns.TypeTXT})
		}
	}
	run(queries)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	// DANE: TLSA records of every mail server.
	all := append(slices.Clone(records), out...)
	queries = nil
	for _, r := range all {
		if r.Type == "MX" && slices.Contains(mailDomains, r.Host) {
			mx := normalizeName(mxHost(r.Value))
			if mx != "" && mx != "." {
				queries = append(queries, query{"_25._tcp." + mx, miekgdns.TypeTLSA})
			}
		}
	}
	slices.SortFunc(queries, func(a, b query) int { return strings.Compare(a.name, b.name) })
	queries = slices.Compact(queries)
	run(queries)

	// SPF includes and redirects, breadth first.
	seen := map[string]bool{}
	for _, d := range mailDomains {
		seen[d] = true
	}
	next := spfTargets(append(slices.Clone(records), out...), mailDomains)
	for len(next) > 0 && len(seen) < len(mailDomains)+maxSPFIncludes {
		queries = nil
		for _, d := range next {
			if !seen[d] && len(seen) < len(mailDomains)+maxSPFIncludes {
				seen[d] = true
				queries = append(queries, query{d, miekgdns.TypeTXT})
			}
		}
		before := len(out)
		run(queries)
		var names []string
		for _, qu := range queries {
			names = append(names, qu.name)
		}
		next = spfTargets(out[before:], names)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if failed > 0 {
		s.opts.Logger.Warn("dns: some email record lookups failed", "failed", failed)
	}

	// Zone transfers.
	nsRRs, err := q.lookup(ctx, domain, miekgdns.TypeNS)
	if err != nil {
		return nil, nil, err
	}
	var nameservers []string
	for _, rr := range nsRRs {
		if ns, ok := rr.(*miekgdns.NS); ok {
			nameservers = append(nameservers, normalizeName(ns.Ns))
		}
	}
	slices.Sort(nameservers)
	var transfers []ZoneTransfer
	for _, ns := range nameservers {
		if n, ok := zoneTransfer(ctx, domain, net.JoinHostPort(ns, axfrPort)); ok {
			transfers = append(transfers, ZoneTransfer{Nameserver: ns, Records: n})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return out, transfers, nil
}

// rrValues converts an answer to DNS records under name, keeping only records
// of the type asked for (not the CNAMEs leading to them).
func rrValues(name string, qtype uint16, rrs []miekgdns.RR) []DNSRecord {
	var out []DNSRecord
	for _, rr := range rrs {
		var typ, value string
		switch r := rr.(type) {
		case *miekgdns.TXT:
			typ, value = "TXT", strings.Join(r.Txt, "")
		case *miekgdns.MX:
			typ, value = "MX", normalizeName(r.Mx)
		case *miekgdns.TLSA:
			typ, value = "TLSA", fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, r.Certificate)
		default:
			continue
		}
		if miekgdns.StringToType[typ] == qtype {
			out = append(out, DNSRecord{Host: name, Type: typ, Value: value})
		}
	}
	return out
}

// mxHost is the mail server in an MX value, which dnsx gives as the host
// alone and some resolvers as "<preference> <host>".
func mxHost(value string) string {
	f := strings.Fields(value)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// spfTargets lists the domains named by include: and redirect= in the SPF
// records of hosts, in order of appearance.
func spfTargets(records []DNSRecord, hosts []string) []string {
	var out []string
	for _, r := range records {
		if r.Type != "TXT" || !slices.Contains(hosts, r.Host) {
			continue
		}
		terms := strings.Fields(strings.ToLower(r.Value))
		if len(terms) == 0 || terms[0] != "v=spf1" {
			continue
		}
		for _, t := range terms[1:] {
			var target string
			if v, ok := strings.CutPrefix(strings.TrimLeft(t, "+-~?"), "include:"); ok {
				target = v
			} else if v, ok := strings.CutPrefix(t, "redirect="); ok {
				target = v
			}
			// Skip macros (%{...}), which only expand when mail is checked.
			if target = normalizeName(target); target != "" && !strings.Contains(target, "%") && !slices.Contains(out, target) {
				out = append(out, target)
			}
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

// txtValues joins each TXT record's strings into one value.
func txtValues(rrs []miekgdns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*miekgdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
