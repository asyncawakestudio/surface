// Package scan adapts the asm engine for the CLI and MCP front-ends: a shared
// set of parameters, option building, and a run helper. Both a human (CLI) and
// an AI (MCP) drive the same core discovery service through here.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/asyncawakestudio/surface/asm"
)

// Params are the knobs both front-ends expose. By default subdomains, dns,
// ipdr, cloud, web and certs run; the port scan is opt-in (Ports) because it probes every
// resolved IP, including third-party infrastructure. Set the Skip* fields to
// turn stages off. Zero values elsewhere mean "default", except Domain which
// is required.
type Params struct {
	Domain              string
	SkipIPDR            bool
	SkipCerts           bool
	SkipWeb             bool
	SkipCloud           bool
	CloudServices       bool   // guess cloud resources named after the domain
	CloudStorage        bool   // check for public buckets named after the domain
	SubdomainBruteforce bool   // brute-force subdomains after subfinder
	SubdomainWordlist   string // wordlist for SubdomainBruteforce; empty = the built-in top 5,000
	Ports               bool   // run the port scan
	PortType            string // "connect" (default) or "syn"
	PortSpec            string // naabu port spec, e.g. "-", "1-1000", "80,443"
	PortRate            int
	Services            bool   // identify the service on each open port (needs Ports)
	ServiceProbes       string // nmap-service-probes path; empty = local nmap's copy
	Vulns               bool   // look up CVEs for detected services and web technologies
	NVDAPIKey           string // optional; raises NVD's rate limit
	PDCPAPIKey          string // optional; ProjectDiscovery Cloud key for vulnx
	Resolvers           []string
	IPInfoToken         string
	SubfinderCfg        string
	MaxTime             time.Duration
}

// Options converts Params into asm.Options. logs, if non-nil, receives engine
// stage logging; pass nil to discard.
func (p Params) Options(logs *slog.Logger) asm.Options {
	if logs == nil {
		logs = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	// The engine defaults to a SYN scan, which needs root and libpcap; the
	// front-ends default to a connect scan, which works anywhere.
	portType := p.PortType
	if portType == "" {
		portType = "connect"
	}
	return asm.Options{
		SubfinderProviderConfig: p.SubfinderCfg,
		SubfinderMaxTime:        p.MaxTime,
		SubdomainBruteforce:     p.SubdomainBruteforce,
		SubdomainWordlist:       p.SubdomainWordlist,
		Resolvers:               p.Resolvers,
		IPInfoToken:             p.IPInfoToken,
		SkipIPDR:                p.SkipIPDR,
		SkipCerts:               p.SkipCerts,
		SkipWeb:                 p.SkipWeb,
		SkipCloud:               p.SkipCloud,
		CloudServices:           p.CloudServices,
		CloudStorage:            p.CloudStorage,
		PortScan:                p.Ports,
		PortScanType:            portType,
		PortScanPorts:           p.PortSpec,
		PortScanRate:            p.PortRate,
		ServiceDetection:        p.Services,
		ServiceProbesFile:       p.ServiceProbes,
		VulnLookup:              p.Vulns,
		NVDAPIKey:               p.NVDAPIKey,
		PDCPAPIKey:              p.PDCPAPIKey,
		Logger:                  logs,
	}
}

// StageNames are the stages a caller may skip. subdomains and dns are
// foundational (everything depends on them) and cannot be skipped; ports is
// off unless requested.
var StageNames = []string{"ipdr", "cloud", "web", "certs"}

// ApplySkips sets the Skip* fields from stage names, returning an error for an
// unknown or non-skippable name.
func (p *Params) ApplySkips(names []string) error {
	for _, n := range names {
		switch n {
		case "ipdr":
			p.SkipIPDR = true
		case "certs":
			p.SkipCerts = true
		case "web":
			p.SkipWeb = true
		case "cloud":
			p.SkipCloud = true
		case "ports":
			return fmt.Errorf("the port scan is off by default; there is no need to skip it")
		default:
			return fmt.Errorf("cannot skip %q (skippable stages: %s)", n, strings.Join(StageNames, ", "))
		}
	}
	return nil
}

// ErrVulnsNeedInput is returned by Validate when the CVE lookup has nothing to
// work from.
var ErrVulnsNeedInput = errors.New("the vulns lookup needs services or the web stage (it is skipped)")

// ErrWordlistNeedsBruteforce is returned by Validate for a subdomain wordlist
// without brute-forcing.
var ErrWordlistNeedsBruteforce = errors.New("a subdomain wordlist requires subdomain brute-forcing")

// Validate checks combinations of options that wouldn't do anything or that
// the engine would reject.
func (p Params) Validate() error {
	if p.SubdomainWordlist != "" && !p.SubdomainBruteforce {
		return ErrWordlistNeedsBruteforce
	}
	if p.CloudStorage && p.SkipCloud {
		return asm.ErrCloudStorageNeedsCloud
	}
	if p.CloudServices && p.SkipCloud {
		return asm.ErrCloudServicesNeedsCloud
	}
	if p.Vulns && !p.Services && p.SkipWeb {
		return ErrVulnsNeedInput
	}
	return nil
}

// Run normalizes the domain and executes the full pipeline. progress may be
// nil. It is a thin wrapper so the CLI and MCP share identical behavior.
func Run(ctx context.Context, p Params, logs *slog.Logger, progress asm.ProgressFunc) (*asm.Result, error) {
	scanner := asm.New(p.Options(logs))
	return scanner.Run(ctx, asm.Target{Domain: p.Domain}, progress)
}
