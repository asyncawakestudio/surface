package asm

import (
	"context"
	"sync"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// resolvedHost is a host with at least one A/AAAA record.
type resolvedHost struct {
	Host string
	IPs  []string
}

var dnsQuestionTypes = []uint16{
	miekgdns.TypeA,
	miekgdns.TypeAAAA,
	miekgdns.TypeCNAME,
	miekgdns.TypeMX,
	miekgdns.TypeNS,
	miekgdns.TypeTXT,
	miekgdns.TypeCAA,
}

// resolve queries each host with dnsx and flattens the answers into records.
// It also returns the hosts that resolved to an address, for later stages.
func (s *Scanner) resolve(ctx context.Context, hosts []string) ([]DNSRecord, []resolvedHost, error) {
	opts := dnsx.DefaultOptions
	opts.QuestionTypes = dnsQuestionTypes
	opts.MaxRetries = 2
	opts.Hostsfile = false
	if len(s.opts.Resolvers) > 0 {
		opts.BaseResolvers = s.opts.Resolvers
	}

	client, err := dnsx.New(opts)
	if err != nil {
		return nil, nil, err
	}

	type answer struct {
		records  []DNSRecord
		resolved *resolvedHost
	}
	answers := make([]answer, len(hosts))

	forEach(ctx, hosts, s.opts.DNSConcurrency, func(i int, host string) {
		data, err := client.QueryMultiple(host)
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
