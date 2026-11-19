package asm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

//go:embed data/subdomains-top5000.txt
var defaultSubdomainWordlist []byte

// wordlistLabelRe accepts one or more DNS labels ("dev", "mail.internal").
var wordlistLabelRe = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

// wildcardProbes is the number of random names resolved to detect wildcard
// DNS. Several, since a wildcard behind a CDN may answer with rotating IPs.
const wildcardProbes = 3

// bruteforceSubdomains resolves <word>.<domain> for each word in the
// wordlist (SubdomainWordlist, or the embedded SecLists top 5000) and returns
// the names that exist, skipping those already in known. It runs after
// subfinder, as part of the subdomains stage.
//
// When the domain has wildcard DNS every guess resolves, so a name only counts
// if its answer differs from what random names get.
func (s *Scanner) bruteforceSubdomains(ctx context.Context, domain string, known map[string]bool) ([]string, error) {
	words, err := s.subdomainWordlist()
	if err != nil {
		return nil, err
	}
	client, err := newDNSClient(s.dnsResolvers(domain), []uint16{miekgdns.TypeA})
	if err != nil {
		return nil, err
	}
	resolve := func(host string) []string {
		data, err := client.QueryOne(host)
		if err != nil || data == nil || data.StatusCode != miekgdns.RcodeToString[miekgdns.RcodeSuccess] {
			return nil
		}
		return dnsAnswers(data)
	}

	wildcard := map[string]bool{}
	for range wildcardProbes {
		for _, a := range resolve(randomLabel() + "." + domain) {
			wildcard[a] = true
		}
	}

	var hosts []string
	for _, w := range words {
		if h := w + "." + domain; !known[h] {
			hosts = append(hosts, h)
		}
	}
	s.opts.Logger.Info("subdomains: brute-forcing", "candidates", len(hosts), "wildcard", len(wildcard) > 0)

	found := make([]bool, len(hosts))
	forEach(ctx, hosts, s.opts.DNSConcurrency, func(i int, host string) {
		answers := resolve(host)
		found[i] = len(answers) > 0 && !(len(wildcard) > 0 && allIn(answers, wildcard))
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []string
	for i, ok := range found {
		if ok {
			out = append(out, hosts[i])
		}
	}
	s.opts.Logger.Info("subdomains: brute-force done", "found", len(out))
	return out, nil
}

// subdomainWordlist reads the wordlist, lowercased and de-duplicated, keeping
// only entries that are valid DNS labels.
func (s *Scanner) subdomainWordlist() ([]string, error) {
	var r io.Reader = bytes.NewReader(defaultSubdomainWordlist)
	if s.opts.SubdomainWordlist != "" {
		f, err := os.Open(s.opts.SubdomainWordlist)
		if err != nil {
			return nil, fmt.Errorf("subdomain wordlist: %w", err)
		}
		defer f.Close()
		r = f
	}
	var words []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		w := strings.Trim(strings.ToLower(strings.TrimSpace(sc.Text())), ".")
		if w == "" || seen[w] || !wordlistLabelRe.MatchString(w) {
			continue
		}
		seen[w] = true
		words = append(words, w)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("subdomain wordlist: %w", err)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("subdomain wordlist %q has no valid entries", s.opts.SubdomainWordlist)
	}
	return words, nil
}

// dnsAnswers lists a response's addresses and CNAME targets.
func dnsAnswers(data *retryabledns.DNSData) []string {
	var out []string
	out = append(out, data.A...)
	out = append(out, data.AAAA...)
	for _, c := range data.CNAME {
		out = append(out, normalizeName(c))
	}
	return out
}

func allIn(values []string, set map[string]bool) bool {
	for _, v := range values {
		if !set[v] {
			return false
		}
	}
	return true
}

// randomLabel is a name no one would register: "surface-wildcard-<hex>".
func randomLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "surface-wildcard-" + hex.EncodeToString(b)
}
