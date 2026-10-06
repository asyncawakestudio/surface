package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// IPInfo is the ipinfo.io record for one IP address. Data is the API
// response exactly as returned (fields vary by plan); Error is set instead
// when the lookup failed.
type IPInfo struct {
	IP    string          `json:"ip"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error,omitempty"`
}

const ipinfoMaxBody = 64 << 10

// lookupIPs fetches ipinfo.io data for every public address the resolved
// hosts point at. Failed lookups (rate limits, timeouts) are recorded per IP
// rather than failing the scan.
func (s *Scanner) lookupIPs(ctx context.Context, hosts []resolvedHost) ([]IPInfo, error) {
	ips := publicIPs(hosts)
	out := make([]IPInfo, len(ips))
	forEach(ctx, ips, s.opts.IPInfoConcurrency, func(i int, ip string) {
		data, err := s.fetchIPInfo(ctx, ip)
		out[i] = IPInfo{IP: ip, Data: data}
		if err != nil {
			out[i].Error = err.Error()
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var failed int
	for _, info := range out {
		if info.Error != "" {
			failed++
		}
	}
	if failed > 0 {
		s.opts.Logger.Warn("ipinfo: some lookups failed", "failed", failed, "total", len(out))
	}
	return out, nil
}

func (s *Scanner) fetchIPInfo(ctx context.Context, ip string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opts.IPInfoBaseURL+"/"+ip+"/json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if s.opts.IPInfoToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.opts.IPInfoToken)
	}

	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, ipinfoMaxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("ipinfo: HTTP %d: %s", resp.StatusCode, msg)
	}

	// Only accept a JSON object; it's stored and rendered as key/value data.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("ipinfo: invalid JSON response")
	}
	return json.RawMessage(body), nil
}

// publicIPs returns the unique, globally routable addresses of hosts,
// sorted. Private, loopback, link-local and other reserved ranges are never
// sent to ipinfo.
func publicIPs(hosts []resolvedHost) []string {
	seen := map[netip.Addr]bool{}
	var addrs []netip.Addr
	for _, h := range hosts {
		for _, s := range h.IPs {
			a, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			a = a.Unmap()
			if seen[a] || !a.IsGlobalUnicast() || a.IsPrivate() || isReserved(a) {
				continue
			}
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

func isReserved(a netip.Addr) bool {
	for _, p := range reservedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
