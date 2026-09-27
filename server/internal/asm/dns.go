package asm

import (
	"context"
	"net"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// resolvedHost is a host with at least one A/AAAA record.
type resolvedHost struct {
	Host string
	IPs  []string
}

// dnsQuestionTypes are queried in order for every live host. A must come
// first: retryabledns retries a type that returns no data only while the
// accumulated answer is still empty, so once A is filled the usually-empty
// MX/TXT/CAA lookups on subdomains cost one query each instead of MaxRetries.
var dnsQuestionTypes = []uint16{
	miekgdns.TypeA,
	miekgdns.TypeAAAA,
	miekgdns.TypeCNAME,
	miekgdns.TypeMX,
	miekgdns.TypeNS,
	miekgdns.TypeTXT,
	miekgdns.TypeCAA,
}

const (
	dnsTimeout    = 2 * time.Second
	dnsMaxRetries = 2
)

// resolve queries each host with dnsx and flattens the answers into records.
// It also returns the hosts that resolved to an address, for later stages.
//
// It runs in two phases. Passive sources return many names that no longer
// exist, and every record type queried for a dead name costs MaxRetries
// lookups, so a single A query first filters out NXDOMAIN hosts and only the
// rest get the full set of record types.
func (s *Scanner) resolve(ctx context.Context, domain string, hosts []string) ([]DNSRecord, []resolvedHost, error) {
	resolvers := s.dnsResolvers(domain)

	probe, err := newDNSClient(resolvers, []uint16{miekgdns.TypeA})
	if err != nil {
		return nil, nil, err
	}
	full, err := newDNSClient(resolvers, dnsQuestionTypes)
	if err != nil {
		return nil, nil, err
	}

	// Phase 1: drop names that don't exist. NOERROR with no A record is kept,
	// since the name may still have AAAA, MX or TXT records, and so is a
	// dangling CNAME (NXDOMAIN at the target), a subdomain takeover candidate.
	exists := make([]bool, len(hosts))
	forEach(ctx, hosts, s.opts.DNSConcurrency, func(i int, host string) {
		data, err := probe.QueryOne(host)
		exists[i] = err == nil && data != nil &&
			(data.StatusCode == miekgdns.RcodeToString[miekgdns.RcodeSuccess] || len(data.CNAME) > 0)
	})
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var live []string
	for i, ok := range exists {
		if ok {
			live = append(live, hosts[i])
		}
	}
	s.opts.Logger.Info("dns: existing hosts", "total", len(hosts), "existing", len(live))

	// Phase 2: every record type for the hosts that exist.
	type answer struct {
		records  []DNSRecord
		resolved *resolvedHost
	}
	answers := make([]answer, len(live))

	forEach(ctx, live, s.opts.DNSConcurrency, func(i int, host string) {
		data, err := full.QueryMultiple(host)
		if err != nil || data == nil {
			return
		}

		var recs []DNSRecord
		add := func(typ string, values []string) {
			for _, v := range values {
				recs = append(recs, DNSRecord{Host: host, Type: typ, Value: v})
			}
		}
		add("A", data.A)
		add("AAAA", data.AAAA)
		add("CNAME", data.CNAME)
		add("MX", data.MX)
		add("NS", data.NS)
		add("TXT", data.TXT)
		add("CAA", data.CAA)

		answers[i].records = recs
		if ips := append(append([]string{}, data.A...), data.AAAA...); len(ips) > 0 {
			answers[i].resolved = &resolvedHost{Host: host, IPs: ips}
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var records []DNSRecord
	var resolved []resolvedHost
	for _, a := range answers {
		records = append(records, a.records...)
		if a.resolved != nil {
			resolved = append(resolved, *a.resolved)
		}
	}
	return records, resolved, nil
}

// dnsResolvers returns the resolvers to use for this scan. Explicitly
// configured resolvers are used as-is. Otherwise dnsx's public resolvers are
// used if they answer, falling back to the system resolver: some networks
// (corporate, WSL2, some Docker setups) drop UDP/53 to public resolvers, and
// without the fallback every lookup would silently time out.
func (s *Scanner) dnsResolvers(domain string) []string {
	if len(s.opts.Resolvers) > 0 {
		return s.opts.Resolvers
	}
	if resolversReachable(dnsx.DefaultResolvers, domain) {
		return dnsx.DefaultResolvers
	}
	sys := systemResolvers()
	if len(sys) == 0 {
		s.opts.Logger.Warn("dns: public resolvers unreachable and no system resolver found")
		return dnsx.DefaultResolvers
	}
	s.opts.Logger.Warn("dns: public resolvers unreachable, using system resolver", "resolvers", sys)
	return sys
}

func resolversReachable(resolvers []string, domain string) bool {
	c, err := dnsx.New(dnsx.Options{
		BaseResolvers: resolvers,
		MaxRetries:    3, // rotates across resolvers
		QuestionTypes: []uint16{miekgdns.TypeNS},
		Timeout:       dnsTimeout,
	})
	if err != nil {
		return false
	}
	// Any response (even NXDOMAIN) proves the resolvers are reachable; only
	// transport errors mean they aren't.
	data, err := c.QueryOne(domain)
	return err == nil && data != nil && data.StatusCode != ""
}

func systemResolvers() []string {
	conf, err := miekgdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(conf.Servers))
	for _, srv := range conf.Servers {
		out = append(out, "udp:"+net.JoinHostPort(srv, conf.Port))
	}
	return out
}

func newDNSClient(resolvers []string, types []uint16) (*dnsx.DNSX, error) {
	return dnsx.New(dnsx.Options{
		BaseResolvers: resolvers,
		MaxRetries:    dnsMaxRetries,
		QuestionTypes: types,
		Timeout:       dnsTimeout,
	})
}

// forEach calls fn for every item using up to n goroutines. It stops handing
// out new items once ctx is cancelled.
func forEach[T any](ctx context.Context, items []T, n int, fn func(int, T)) {
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, item := range items {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(i, item)
		}()
	}
	wg.Wait()
}
