package asm

import (
	"context"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	contextutil "github.com/projectdiscovery/utils/context"
)

// enumerateSubdomains runs subfinder against domain, equivalent to the CLI
// command `subfinder -d <domain> -all -silent`: every source (including the
// slow ones) with silent output. The root domain itself is always included
// so later stages cover it too.
func (s *Scanner) enumerateSubdomains(ctx context.Context, domain string) ([]Subdomain, error) {
	sf, err := runner.NewRunner(&runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: int(s.opts.SubfinderMaxTime.Minutes()),
		ProviderConfig:     s.opts.SubfinderProviderConfig,
		All:                true, // -all: use all sources
		Silent:             true, // -silent: subdomains only, no extra output
		DisableUpdateCheck: true,
	})
	if err != nil {
		return nil, err
	}

	// The subfinder CLI injects the "All" flag into the context, which some
	// sources (e.g. crtsh) read to widen their queries. EnumerateSingleDomain
	// bypasses that wiring, so set it here to match `-all` behavior.
	ctx, err = contextutil.WithValues(ctx, contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(true)))
	if err != nil {
		return nil, err
	}

	sourceMap, err := sf.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, ok := sourceMap[domain]; !ok {
		sourceMap[domain] = map[string]struct{}{"input": {}}
	}

	out := make([]Subdomain, 0, len(sourceMap))
	for host, sources := range sourceMap {
		srcs := make([]string, 0, len(sources))
		for src := range sources {
			srcs = append(srcs, src)
		}
		slices.Sort(srcs)
		out = append(out, Subdomain{Host: host, Sources: srcs})
	}
	slices.SortFunc(out, func(a, b Subdomain) int { return strings.Compare(a.Host, b.Host) })
	return out, nil
}
