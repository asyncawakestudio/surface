// Package scan adapts the asm engine for the CLI and MCP front-ends: a shared
// set of parameters, option building, and a run helper. Both a human (CLI) and
// an AI (MCP) drive the same core discovery service through here.
package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"surface/asm"
)

// Params are the knobs both front-ends expose. By default every stage runs
// (subdomains, dns, ipinfo, ports, tls) and the port scan covers all ports.
// Set the Skip* fields to turn stages off. Zero values elsewhere mean "engine
// default", except Domain which is required.
type Params struct {
	Domain       string
	SkipIPInfo   bool
	SkipPorts    bool
	SkipTLS      bool
	PortType     string // "syn" or "connect"
	PortSpec     string // naabu port spec, e.g. "-", "1-1000", "80,443"
	PortRate     int
	Resolvers    []string
	IPInfoToken  string
	SubfinderCfg string
	MaxTime      time.Duration
}

// Options converts Params into asm.Options. logs, if non-nil, receives engine
// stage logging; pass nil to discard.
func (p Params) Options(logs *slog.Logger) asm.Options {
	if logs == nil {
		logs = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return asm.Options{
		SubfinderProviderConfig: p.SubfinderCfg,
		SubfinderMaxTime:        p.MaxTime,
		Resolvers:               p.Resolvers,
		IPInfoToken:             p.IPInfoToken,
		SkipIPInfo:              p.SkipIPInfo,
		SkipTLS:                 p.SkipTLS,
		PortScan:                !p.SkipPorts, // ports run by default
		PortScanType:            p.PortType,
		PortScanPorts:           p.PortSpec,
		PortScanRate:            p.PortRate,
		Logger:                  logs,
	}
}

// StageNames are the stages a caller may skip. subdomains and dns are
// foundational (everything depends on them) and cannot be skipped.
var StageNames = []string{"ipinfo", "ports", "tls"}

// ApplySkips sets the Skip* fields from stage names, returning an error for an
// unknown or non-skippable name.
func (p *Params) ApplySkips(names []string) error {
	for _, n := range names {
		switch n {
		case "ipinfo":
			p.SkipIPInfo = true
		case "ports":
			p.SkipPorts = true
		case "tls":
			p.SkipTLS = true
		default:
			return fmt.Errorf("cannot skip %q (skippable stages: %s)", n, strings.Join(StageNames, ", "))
		}
	}
	return nil
}

// Run normalizes the domain and executes the full pipeline. progress may be
// nil. It is a thin wrapper so the CLI and MCP share identical behavior.
func Run(ctx context.Context, p Params, logs *slog.Logger, progress asm.ProgressFunc) (*asm.Result, error) {
	scanner := asm.New(p.Options(logs))
	return scanner.Run(ctx, asm.Target{Domain: p.Domain}, progress)
}
