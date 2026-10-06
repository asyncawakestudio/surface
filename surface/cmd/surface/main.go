// Command surface is the human-facing CLI for the core discovery service.
//
//	surface example.com                 # full scan, human-readable report
//	surface --json example.com          # machine-readable JSON
//	surface --skip=certs,ports example.com
//
// It runs the same engine the MCP server and the cloud product use.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"surface/asm"
	"surface/internal/output"
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
  surface [flags] <domain>
  surface version

By default every stage runs — subdomains, dns, ipdr, ports (all 65535), certs.

Output:
  --output <dest>       where/how to write results (default: txt to stdout).
                        A file path picks the format by extension
                        (report.json, hosts.csv, out.xml, scan.txt); a bare
                        format name (json, csv, xml, txt) writes to stdout.
  --skip <stages>       comma-separated stages to skip: ipdr, ports, certs
                        (subdomains and dns are always run)
  --quiet               suppress progress logging on stderr

Tuning (all optional):
  --ipinfo-token <tok>      ipinfo.io API token
  --subfinder-config <f>    subfinder provider-config.yaml with API keys
                            (defaults to subfinder's own ~/.config path)
  --resolvers <list>        comma-separated DNS resolvers, e.g. udp:1.1.1.1:53
  --max-time <dur>          subfinder enumeration cap, e.g. 10m
  --port-type <t>           syn | connect (default connect)
  --port-spec <s>           -, 1-1000, 80,443 (default -)
  --port-rate <n>           packets/sec for the port scan
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	var (
		outDest   = fs.String("output", "", "output destination: a file path (format by extension) or a format name; empty = txt to stdout")
		skip      = fs.String("skip", "", "comma-separated stages to skip: ipdr, ports, certs")
		quiet     = fs.Bool("quiet", false, "suppress progress logging on stderr")
		ipToken   = fs.String("ipinfo-token", "", "ipinfo.io API token")
		sfConfig  = fs.String("subfinder-config", "", "subfinder provider-config.yaml")
		resolvers = fs.String("resolvers", "", "comma-separated DNS resolvers")
		maxTime   = fs.String("max-time", "", "subfinder enumeration cap, e.g. 10m")
		portType  = fs.String("port-type", "", "port scan mode: syn or connect")
		portSpec  = fs.String("port-spec", "", "ports to scan: -, 1-1000, 80,443")
		portRate  = fs.Int("port-rate", 0, "packets/sec for the port scan")
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
	outFormat, outFile, err := resolveOutput(*outDest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	p := scan.Params{
		Domain:       rest[0],
		PortType:     *portType,
		PortSpec:     *portSpec,
		PortRate:     *portRate,
		IPInfoToken:  *ipToken,
		SubfinderCfg: *sfConfig,
	}
	if *skip != "" {
		if err := p.ApplySkips(splitComma(*skip)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}
	if *resolvers != "" {
		p.Resolvers = splitComma(*resolvers)
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

	w := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot create output file:", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if err := output.Render(w, res, outFormat); err != nil {
		fmt.Fprintln(os.Stderr, "error: writing output:", err)
		return 1
	}
	if outFile != "" && !*quiet {
		fmt.Fprintf(os.Stderr, "wrote %s output to %s\n", outFormat, outFile)
	}
	return 0
}

// resolveOutput maps the --output value to a format and an optional file path.
// Empty -> txt on stdout. A bare format name (json/csv/xml/txt) -> that format
// on stdout. Anything else is a file path whose extension selects the format.
func resolveOutput(dest string) (format, file string, err error) {
	if dest == "" {
		return "txt", "", nil
	}
	if ext := strings.TrimPrefix(filepath.Ext(dest), "."); ext != "" {
		ext = strings.ToLower(ext)
		if !output.Valid(ext) {
			return "", "", fmt.Errorf("unknown output extension %q (valid: %s)", ext, strings.Join(output.Formats, ", "))
		}
		return ext, dest, nil
	}
	if output.Valid(strings.ToLower(dest)) {
		return strings.ToLower(dest), "", nil
	}
	return "", "", fmt.Errorf("cannot determine format from --output %q; use a format name (%s) or a file with one of those extensions", dest, strings.Join(output.Formats, ", "))
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
