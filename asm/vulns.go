package asm

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/cvemap"
)

// ErrVulnLookupNeedsServices is returned when the vulnerability lookup is
// requested without the service detection it works from.
var ErrVulnLookupNeedsServices = errors.New("vulnerability lookup requires service detection (Options.ServiceDetection)")

// Vulnerability is a CVE affecting a detected service's version.
//
// Matching comes from NVD, which checks the service's versioned CPE against
// each CVE's affected version ranges. Exploitation data (KEV, EPSS, public
// PoCs, Nuclei templates) comes from ProjectDiscovery's vulnerability API
// (vulnx); Enriched is false when that lookup failed or knew nothing.
type Vulnerability struct {
	// ID is the CVE ID, e.g. "CVE-2024-6387".
	ID string `json:"id"`
	// Severity is the CVSS severity: "critical", "high", "medium", "low" or
	// "none"; empty when NVD has no score yet.
	Severity string `json:"severity,omitempty"`
	// CVSSScore is the CVSS base score (v4.0, else v3.x, else v2).
	CVSSScore float64 `json:"cvss_score,omitempty"`
	// Description is NVD's English description.
	Description string `json:"description,omitempty"`
	// Published is when the CVE was published.
	Published time.Time `json:"published,omitzero"`

	// Enriched reports whether the fields below come from vulnx.
	Enriched bool `json:"enriched"`
	// Name is a short title, e.g. "OpenSSH - Command Injection".
	Name string `json:"name,omitempty"`
	// KEV reports whether it is on CISA's Known Exploited Vulnerabilities list.
	KEV bool `json:"kev,omitempty"`
	// EPSSScore is the probability of exploitation in the next 30 days (0-1).
	EPSSScore float64 `json:"epss_score,omitempty"`
	// EPSSPercentile ranks EPSSScore against all CVEs (0-1).
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	// PoCs is the number of public proof-of-concept exploits.
	PoCs int `json:"pocs,omitempty"`
	// NucleiTemplate reports whether a Nuclei template detects it.
	NucleiTemplate bool `json:"nuclei_template,omitempty"`
	// Remote reports whether it is exploitable over the network.
	Remote bool `json:"remote,omitempty"`
	// PatchAvailable reports whether a fix is available.
	PatchAvailable bool `json:"patch_available,omitempty"`
}

// ServiceVulnerabilities lists the CVEs matched to one detected service.
type ServiceVulnerabilities struct {
	ServiceTarget
	// CPE is the versioned CPE the CVEs were matched on.
	CPE string `json:"cpe"`
	// Vulnerabilities are sorted by severity (KEV first), then ID.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// lookupVulns finds the CVEs affecting each detected service's version. Only
// CPEs with a version are looked up: a version-less CPE would match every CVE
// ever filed against the product. Each unique CPE is queried once.
func (s *Scanner) lookupVulns(ctx context.Context, services []ServiceTarget) ([]ServiceVulnerabilities, error) {
	type match struct {
		svc ServiceTarget
		cpe string
	}
	var matches []match
	var cpes []string
	seen := map[string]bool{}
	for _, svc := range services {
		for _, cpe := range svc.Service.CPEs {
			if !cpeHasVersion(cpe) {
				continue
			}
			matches = append(matches, match{svc: svc, cpe: cpe})
			if !seen[cpe] {
				seen[cpe] = true
				cpes = append(cpes, cpe)
			}
		}
	}
	if len(cpes) == 0 {
		return nil, nil
	}
	s.opts.Logger.Info("vulns: looking up CVEs", "cpes", len(cpes), "nvd_key", s.opts.NVDAPIKey != "")

	// NVD is rate limited, so the per-CPE lookups run one at a time.
	nvd := newNVDClient(s.opts.NVDBaseURL, s.opts.NVDAPIKey, s.opts.HTTPClient)
	byCPE := make(map[string][]Vulnerability, len(cpes))
	ids := map[string]bool{}
	for _, cpe := range cpes {
		cves, err := nvd.cvesForCPE(ctx, cpe)
		if err != nil {
			return nil, err
		}
		for _, cve := range cves {
			score, sev := cve.severity()
			byCPE[cpe] = append(byCPE[cpe], Vulnerability{
				ID:          cve.ID,
				Severity:    sev,
				CVSSScore:   score,
				Description: cve.description(),
				Published:   cve.published(),
			})
			ids[cve.ID] = true
		}
	}

	enrichment := s.enrichVulns(ctx, slices.Sorted(maps.Keys(ids)))
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var out []ServiceVulnerabilities
	for _, m := range matches {
		vulns := slices.Clone(byCPE[m.cpe])
		if len(vulns) == 0 {
			continue
		}
		for i := range vulns {
			if e, ok := enrichment[vulns[i].ID]; ok {
				vulns[i].applyEnrichment(e)
			}
		}
		slices.SortFunc(vulns, compareVulns)
		out = append(out, ServiceVulnerabilities{ServiceTarget: m.svc, CPE: m.cpe, Vulnerabilities: vulns})
	}
	return out, nil
}

// enrichVulns fetches vulnx data for each CVE ID. Failures are logged and
// skipped: the CVEs are still reported, just without exploitation data.
func (s *Scanner) enrichVulns(ctx context.Context, ids []string) map[string]*cvemap.Vulnerability {
	if len(ids) == 0 {
		return nil
	}
	opts := []cvemap.Option{cvemap.WithBaseURL(s.opts.VulnxBaseURL)}
	if s.opts.PDCPAPIKey != "" {
		opts = append(opts, cvemap.WithPDCPKey(s.opts.PDCPAPIKey))
	}
	client, err := cvemap.New(opts...)
	if err != nil {
		s.opts.Logger.Warn("vulns: vulnx client", "err", err)
		return nil
	}
	params := &cvemap.GetByIDParams{Fields: []string{
		"cve_id", "name", "is_kev", "epss_score", "epss_percentile",
		"poc_count", "is_template", "is_remote", "is_patch_available",
	}}

	results := make([]*cvemap.Vulnerability, len(ids))
	var failed atomic.Int32
	forEach(ctx, ids, s.opts.VulnConcurrency, func(i int, id string) {
		resp, err := client.GetVulnerabilityByID(ctx, id, params)
		if err != nil || resp.Data == nil {
			if !errors.Is(err, cvemap.ErrNotFound) {
				failed.Add(1)
			}
			return
		}
		results[i] = resp.Data
	})
	if n := failed.Load(); n > 0 {
		s.opts.Logger.Warn("vulns: vulnx enrichment failed for some CVEs", "failed", n, "of", len(ids))
	}

	out := make(map[string]*cvemap.Vulnerability, len(ids))
	for i, r := range results {
		if r != nil {
			out[ids[i]] = r
		}
	}
	return out
}

func (v *Vulnerability) applyEnrichment(e *cvemap.Vulnerability) {
	v.Enriched = true
	v.Name = e.Name
	v.KEV = e.IsKev
	v.EPSSScore = e.EpssScore
	v.EPSSPercentile = e.EpssPercentile
	v.PoCs = e.PocCount
	v.NucleiTemplate = e.IsTemplate
	v.Remote = e.IsRemote
	v.PatchAvailable = e.IsPatchAvailable
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// compareVulns orders known-exploited first, then by severity, CVSS score and
// ID (newest IDs of equal rank first).
func compareVulns(a, b Vulnerability) int {
	if a.KEV != b.KEV {
		if a.KEV {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(severityRank[b.Severity], severityRank[a.Severity]); c != 0 {
		return c
	}
	if c := cmp.Compare(b.CVSSScore, a.CVSSScore); c != 0 {
		return c
	}
	return strings.Compare(b.ID, a.ID)
}

// cpeHasVersion reports whether a CPE 2.3 name pins a specific version.
func cpeHasVersion(cpe string) bool {
	fields := splitCPE23(strings.TrimPrefix(cpe, "cpe:2.3:"))
	return len(fields) > 3 && fields[3] != "*" && fields[3] != "-" && fields[3] != ""
}

// cpeVendorProduct returns a CPE 2.3 name's vendor and product.
func cpeVendorProduct(cpe string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", false
	}
	fields := splitCPE23(strings.TrimPrefix(cpe, "cpe:2.3:"))
	if len(fields) < 3 {
		return "", "", false
	}
	return strings.ToLower(fields[1]), strings.ToLower(fields[2]), true
}
