// Command surface is the human-facing CLI for the core discovery service.
//
//	surface example.com                 # full scan, human-readable report
//	surface --json example.com          # machine-readable JSON
//	surface --skip=tls,ports example.com
//
// It runs the same engine the MCP server and the cloud product use.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"surface/asm"
	"surface/internal/scan"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println("surface", version)
	case "help", "-h", "--help":
		usage()
	default:
		// Everything else is a scan: `surface [flags] <domain>`.
		os.Exit(runScan(os.Args[1:]))
	}
}

var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `surface — attack surface discovery

Usage:
  surface [--json] [--quiet] [--skip=<stages>] <domain>
  surface version

By default every stage runs — subdomains, dns, ipinfo, ports (all 65535), tls.

Flags:
  --json           output JSON instead of a text report
  --quiet          suppress progress logging on stderr
  --skip=<stages>  comma-separated stages to skip: ipinfo, ports, tls
                   (subdomains and dns are always run)

Advanced tuning is read from the environment (all optional):
  IPINFO_TOKEN              ipinfo.io API token
  SUBFINDER_PROVIDER_CONFIG subfinder provider-config.yaml with API keys
                            (defaults to subfinder's own ~/.config path)
  DNS_RESOLVERS             comma-separated, e.g. udp:1.1.1.1:53
  SUBFINDER_MAX_TIME        subfinder cap, e.g. 10m
  PORT_SCAN_TYPE            syn | connect (default connect)
  PORT_SCAN_PORTS           -, 1-1000, 80,443 (default -)
  PORT_SCAN_RATE            packets/sec
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	var (
		jsonOut = fs.Bool("json", false, "output JSON instead of a text report")
		quiet   = fs.Bool("quiet", false, "suppress progress logging on stderr")
		skip    = fs.String("skip", "", "comma-separated stages to skip: ipinfo, ports, tls")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "error: exactly one <domain> is required (put flags before the domain)")
		usage()
		return 2
	}

	// Common usage is just `surface <domain>`; everything else is tuned
	// through the environment, matching how surface-cloud is configured.
	p := scan.Params{
		Domain:       rest[0],
		PortType:     os.Getenv("PORT_SCAN_TYPE"),
		PortSpec:     os.Getenv("PORT_SCAN_PORTS"),
		PortRate:     envInt("PORT_SCAN_RATE"),
		IPInfoToken:  os.Getenv("IPINFO_TOKEN"),
		SubfinderCfg: os.Getenv("SUBFINDER_PROVIDER_CONFIG"),
	}
	if *skip != "" {
		if err := p.ApplySkips(splitComma(*skip)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}
	if r := os.Getenv("DNS_RESOLVERS"); r != "" {
		p.Resolvers = splitComma(r)
	}
	if mt := os.Getenv("SUBFINDER_MAX_TIME"); mt != "" {
		d, err := time.ParseDuration(mt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid SUBFINDER_MAX_TIME:", err)
			return 2
		}
		p.MaxTime = d
	}

	var logs *slog.Logger
	if !*quiet {
		logs = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	progress := func(stage asm.Stage) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "==> %s\n", stage)
		}
	}

	res, err := scan.Run(ctx, p, logs, progress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		return 1
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			return 1
		}
		return 0
	}
	printReport(os.Stdout, res)
	return 0
}

func printReport(w *os.File, r *asm.Result) {
	fmt.Fprintf(w, "\nSurface report for %s\n", r.Domain)
	fmt.Fprintf(w, "%s\n", strings.Repeat("=", 40))

	fmt.Fprintf(w, "\nSubdomains (%d)\n", len(r.Subdomains))
	for _, s := range r.Subdomains {
		tag := ""
		if s.CarriedOver {
			tag = "  [carried over]"
		}
		fmt.Fprintf(w, "  %s%s\n", s.Host, tag)
	}

	fmt.Fprintf(w, "\nDNS records (%d)\n", len(r.DNSRecords))
	for _, d := range r.DNSRecords {
		fmt.Fprintf(w, "  %-40s %-6s %s\n", d.Host, d.Type, d.Value)
	}

	fmt.Fprintf(w, "\nIP info (%d)\n", len(r.IPInfo))
	for _, i := range r.IPInfo {
		if i.Error != "" {
			fmt.Fprintf(w, "  %-18s error: %s\n", i.IP, i.Error)
			continue
		}
		fmt.Fprintf(w, "  %-18s %s\n", i.IP, summarizeIPInfo(i.Data))
	}

	if len(r.PortScans) > 0 {
		fmt.Fprintf(w, "\nOpen ports\n")
		for _, ps := range r.PortScans {
			ports := make([]string, len(ps.Ports))
			for j, p := range ps.Ports {
				ports[j] = fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			}
			fmt.Fprintf(w, "  %-18s %s\n", ps.IP, strings.Join(ports, ", "))
		}
	}

	fmt.Fprintf(w, "\nTLS certificates (%d)\n", len(r.TLSCerts))
	for _, c := range r.TLSCerts {
		flags := certFlags(c)
		fmt.Fprintf(w, "  %s:%d  %s  (issuer: %s)%s\n", c.Host, c.Port, c.SubjectCN, c.IssuerCN, flags)
	}
	fmt.Fprintln(w)
}

func certFlags(c asm.TLSCert) string {
	var f []string
	if c.Expired {
		f = append(f, "expired")
	}
	if c.SelfSigned {
		f = append(f, "self-signed")
	}
	if c.Mismatched {
		f = append(f, "mismatched")
	}
	if len(f) == 0 {
		return ""
	}
	return "  [" + strings.Join(f, ", ") + "]"
}

func summarizeIPInfo(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	var parts []string
	for _, k := range []string{"org", "city", "region", "country"} {
		if v, ok := m[k].(string); ok && v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " · ")
}

func envInt(key string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
		return n
	}
	return 0
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return slices.Clip(out)
}
