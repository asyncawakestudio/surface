package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NVD rate limits are 5 requests per 30s without an API key and 50 with one.
// These intervals keep a little under them.
const (
	nvdIntervalNoKey = 6500 * time.Millisecond
	nvdIntervalKey   = 700 * time.Millisecond
	nvdPageSize      = 2000 // NVD's maximum
	nvdMaxAttempts   = 3
)

// nvdClient queries the NVD CVE API 2.0. It is safe for concurrent use; requests
// are spaced to respect NVD's rate limit.
type nvdClient struct {
	baseURL  string
	apiKey   string
	http     *http.Client
	interval time.Duration

	mu   sync.Mutex
	next time.Time // earliest time the next request may start
}

func newNVDClient(baseURL, apiKey string, hc *http.Client) *nvdClient {
	interval := nvdIntervalNoKey
	if apiKey != "" {
		interval = nvdIntervalKey
	}
	return &nvdClient{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: hc, interval: interval}
}

// nvdCVE is the subset of an NVD CVE record surface uses.
type nvdCVE struct {
	ID           string    `json:"id"`
	Published    string    `json:"published"`
	Descriptions []nvdText `json:"descriptions"`
	Metrics      struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Criteria   string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	Type     string `json:"type"` // "Primary" (NVD) or "Secondary" (CNA)
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"` // CVSS v3/v4
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSS v2
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// cvesForCPE returns the CVEs NVD lists as affecting cpe, a versioned CPE 2.3
// name. NVD matches it against each CVE's affected version ranges
// (virtualMatchString); CVEs where the product only appears as a platform it
// runs on, not as the vulnerable component, are dropped.
func (c *nvdClient) cvesForCPE(ctx context.Context, cpe string) ([]nvdCVE, error) {
	vendor, product, ok := cpeVendorProduct(cpe)
	if !ok {
		return nil, fmt.Errorf("nvd: invalid CPE %q", cpe)
	}
	var out []nvdCVE
	for start := 0; ; {
		q := url.Values{}
		q.Set("virtualMatchString", cpe)
		q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
		q.Set("startIndex", strconv.Itoa(start))
		var page nvdPage
		if err := c.get(ctx, "/rest/json/cves/2.0?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, v := range page.Vulnerabilities {
			if affectsProduct(v.CVE, vendor, product) {
				out = append(out, v.CVE)
			}
		}
		start += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
			return out, nil
		}
	}
}

// affectsProduct reports whether one of cve's vulnerable configurations names
// vendor:product.
func affectsProduct(cve nvdCVE, vendor, product string) bool {
	for _, cfg := range cve.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				if v, p, ok := cpeVendorProduct(m.Criteria); ok && v == vendor && p == product {
					return true
				}
			}
		}
	}
	return false
}

// get performs a rate-limited GET, retrying when NVD throttles (403/429) or is
// unavailable (5xx).
func (c *nvdClient) get(ctx context.Context, path string, out any) error {
	var lastErr error
	for attempt := 1; attempt <= nvdMaxAttempts; attempt++ {
		if err := c.wait(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
		if err != nil {
			return err
		}
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("nvd: %w", err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case err != nil:
			lastErr = fmt.Errorf("nvd: reading response: %w", err)
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("nvd: decoding response: %w", err)
			}
			return nil
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
			c.backoff(time.Duration(attempt) * c.interval)
		default:
			return fmt.Errorf("nvd: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
		}
	}
	return lastErr
}

// wait blocks until the next request may start under the rate limit.
func (c *nvdClient) wait(ctx context.Context) error {
	c.mu.Lock()
	now := time.Now()
	start := now
	if c.next.After(now) {
		start = c.next
	}
	c.next = start.Add(c.interval)
	c.mu.Unlock()

	if d := start.Sub(now); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// backoff delays every later request by d, after NVD throttled one.
func (c *nvdClient) backoff(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until := time.Now().Add(d); until.After(c.next) {
		c.next = until
	}
}

// severity returns the CVE's CVSS score and severity: CVSS v4.0, then v3.1,
// v3.0 and v2, preferring NVD's own (Primary) assessment within a version.
func (cve nvdCVE) severity() (float64, string) {
	for _, metrics := range [][]nvdMetric{cve.Metrics.V40, cve.Metrics.V31, cve.Metrics.V30, cve.Metrics.V2} {
		if len(metrics) == 0 {
			continue
		}
		m := metrics[0]
		for _, candidate := range metrics {
			if candidate.Type == "Primary" {
				m = candidate
				break
			}
		}
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		return m.CVSSData.BaseScore, strings.ToLower(sev)
	}
	return 0, ""
}

// description returns the CVE's English description.
func (cve nvdCVE) description() string {
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

// published parses the CVE's publication time (NVD omits the zone; it is UTC).
func (cve nvdCVE) published() time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
