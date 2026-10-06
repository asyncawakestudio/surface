// Command surface is the human-facing CLI for the core discovery service.
//
//	surface scan example.com                 # human-readable report
//	surface scan --json example.com          # machine-readable JSON
//	surface scan --ports --port-type connect example.com
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
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("surface", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `surface — attack surface discovery

Usage:
  surface scan [flags] <domain>
  surface version

Scan flags:
  --json                 output JSON instead of a text report
  --ports                run the port-scan stage (naabu)
  --port-type <t>        port scan mode: syn or connect (default connect)
  --port-spec <s>        ports to scan: "-" all, "1-1000", "80,443" (default -)
  --port-rate <n>        packets/sec for the port scan
  --resolvers <list>     comma-separated DNS resolvers (e.g. udp:1.1.1.1:53)
  --ipinfo-token <tok>   ipinfo.io API token
  --subfinder-config <f> subfinder provider-config.yaml (API keys)
  --max-time <dur>       subfinder max enumeration time (e.g. 10m)
  --quiet                suppress progress logging on stderr
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	var (
		jsonOut  = fs.Bool("json", false, "output JSON instead of a text report")
		ports    = fs.Bool("ports", false, "run the port-scan stage")
		portType = fs.String("port-type", "connect", "port scan mode: syn or connect")
		portSpec = fs.String("port-spec", "", "ports to scan (-, 1-1000, 80,443)")
		portRate = fs.Int("port-rate", 0, "packets/sec for the port scan")
		resolver = fs.String("resolvers", "", "comma-separated DNS resolvers")
		ipToken  = fs.String("ipinfo-token", "", "ipinfo.io API token")
		sfConfig = fs.String("subfinder-config", "", "subfinder provider-config.yaml")
		maxTime  = fs.String("max-time", "", "subfinder max enumeration time (e.g. 10m)")
		quiet    = fs.Bool("quiet", false, "suppress progress logging on stderr")
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

	p := scan.Params{
		Domain:       rest[0],
		Ports:        *ports,
		PortType:     *portType,
		PortSpec:     *portSpec,
		PortRate:     *portRate,
		IPInfoToken:  *ipToken,
		SubfinderCfg: *sfConfig,
	}
	if *resolver != "" {
		p.Resolvers = splitComma(*resolver)
	}
	if *maxTime != "" {
		d, err := time.ParseDuration(*maxTime)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid --max-time:", err)
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

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return slices.Clip(out)
}
