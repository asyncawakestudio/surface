// Package scan adapts the asm engine for the CLI and MCP front-ends: a shared
// set of parameters, option building, and a run helper. Both a human (CLI) and
// an AI (MCP) drive the same core discovery service through here.
package scan

import (
	"context"
	"io"
	"log/slog"
	"time"

	"surface/asm"
)

// Params are the knobs both front-ends expose. Zero values mean "engine
// default", except Domain which is required.
type Params struct {
	Domain       string
	Ports        bool   // run the port-scan stage
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
		PortScan:                p.Ports,
		PortScanType:            p.PortType,
		PortScanPorts:           p.PortSpec,
		PortScanRate:            p.PortRate,
		Logger:                  logs,
	}
}

// Run normalizes the domain and executes the full pipeline. progress may be
// nil. It is a thin wrapper so the CLI and MCP share identical behavior.
func Run(ctx context.Context, p Params, logs *slog.Logger, progress asm.ProgressFunc) (*asm.Result, error) {
	scanner := asm.New(p.Options(logs))
	return scanner.Run(ctx, asm.Target{Domain: p.Domain}, progress)
}
