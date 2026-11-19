// Command surface is the human-facing CLI for the core discovery service.
//
//	surface example.com                 # scan, human-readable report
//	surface --output=json example.com   # machine-readable JSON
//	surface --ports --skip=certs example.com
//	surface --ports --services example.com
//	surface --ports --services --vulns example.com
//	surface --vulns example.com         # CVEs for web technologies only
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

	"github.com/asyncawakestudio/surface/asm"
	"github.com/asyncawakestudio/surface/internal/output"
	"github.com/asyncawakestudio/surface/internal/scan"
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

By default these stages run: subdomains, dns, ipdr, misconfig, web, certs.
The port scan is opt-in (--ports) since it probes every IP the domain resolves
to, including hosting and CDN infrastructure you may not own.

Output:
  --output <dest>       where/how to write results (default: txt to stdout).
                        A file path picks the format by extension
                        (report.json, hosts.csv, out.xml, scan.txt); a bare
                        format name (json, csv, xml, txt) writes to stdout.
  --skip <stages>       comma-separated stages to skip: ipdr, misconfig, web,
                        certs
                        (subdomains and dns are always run)
  --subdomain-brute-force
                        after subfinder, also try each label of a wordlist
                        as <label>.<domain> (one DNS query per label)
  --cloud-storage       also look for public AWS S3, Google Cloud and Azure
                        buckets named after the domain (guesses names)
  --ports               also run the port scan (all 65535 TCP ports by default)
                        (not available in Windows ARM64 builds)
  --services            with --ports, identify the service on each open port
                        (product, version, CPEs) using nmap's service probes;
                        needs nmap installed or --service-probes
  --vulns               look up the CVEs affecting each detected service's
                        and web technology's version (NVD), with exploitation
                        data from ProjectDiscovery's vulnx (KEV, EPSS, PoCs)
  --quiet               suppress progress logging on stderr

Tuning (all optional):
  --ipinfo-token <tok>      ipinfo.io API token
  --subfinder-config <f>    subfinder provider-config.yaml with API keys
                            (defaults to subfinder's own ~/.config path)
  --subdomain-wordlist <f>  wordlist for --subdomain-brute-force, one label per
                            line (default: built-in SecLists top 5,000)
  --resolvers <list>        comma-separated DNS resolvers, e.g. udp:1.1.1.1:53
  --max-time <dur>          subfinder enumeration cap, e.g. 90s or 10m
  --port-type <t>           connect | syn (default connect; syn needs root
                            and libpcap)
  --port-spec <s>           -, 1-1000, 80,443 (default -)
  --port-rate <n>           packets/sec for the port scan
  --service-probes <f>      nmap-service-probes file for --services
                            (defaults to a local nmap installation's copy)
  --nvd-api-key <key>       NVD API key for --vulns: 10x higher rate limit
                            (default: $NVD_API_KEY)
  --pdcp-api-key <key>      ProjectDiscovery Cloud API key for --vulns
                            (default: $PDCP_API_KEY)
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	var (
		outDest   = fs.String("output", "", "output destination: a file path (format by extension) or a format name; empty = txt to stdout")
		skip      = fs.String("skip", "", "comma-separated stages to skip: ipdr, misconfig, web, certs")
		ports     = fs.Bool("ports", false, "also run the port scan")
		quiet     = fs.Bool("quiet", false, "suppress progress logging on stderr")
		ipToken   = fs.String("ipinfo-token", "", "ipinfo.io API token")
		sfConfig  = fs.String("subfinder-config", "", "subfinder provider-config.yaml")
		cloud     = fs.Bool("cloud-storage", false, "look for public cloud storage buckets named after the domain")
		brute     = fs.Bool("subdomain-brute-force", false, "brute-force subdomains from a wordlist after subfinder")
		wordlist  = fs.String("subdomain-wordlist", "", "wordlist for --subdomain-brute-force (default: built-in top 5,000)")
		resolvers = fs.String("resolvers", "", "comma-separated DNS resolvers")
		maxTime   = fs.String("max-time", "", "subfinder enumeration cap, e.g. 10m")
		portType  = fs.String("port-type", "", "port scan mode: connect or syn")
		portSpec  = fs.String("port-spec", "", "ports to scan: -, 1-1000, 80,443")
		portRate  = fs.Int("port-rate", 0, "packets/sec for the port scan")
		services  = fs.Bool("services", false, "identify the service on each open port (needs --ports)")
		probes    = fs.String("service-probes", "", "nmap-service-probes file for --services")
		vulns     = fs.Bool("vulns", false, "look up CVEs for detected services and web technologies")
		nvdKey    = fs.String("nvd-api-key", os.Getenv("NVD_API_KEY"), "NVD API key for --vulns")
		pdcpKey   = fs.String("pdcp-api-key", os.Getenv("PDCP_API_KEY"), "ProjectDiscovery Cloud API key for --vulns")
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

	if !*ports && (*portType != "" || *portSpec != "" || *portRate != 0 || *services) {
		fmt.Fprintln(os.Stderr, "error: --port-type, --port-spec, --port-rate and --services require --ports")
		return 2
	}
	if !*services && *probes != "" {
		fmt.Fprintln(os.Stderr, "error: --service-probes requires --services")
		return 2
	}

	p := scan.Params{
		Domain:              rest[0],
		Ports:               *ports,
		PortType:            *portType,
		PortSpec:            *portSpec,
		PortRate:            *portRate,
		Services:            *services,
		ServiceProbes:       *probes,
		Vulns:               *vulns,
		NVDAPIKey:           *nvdKey,
		PDCPAPIKey:          *pdcpKey,
		IPInfoToken:         *ipToken,
		SubfinderCfg:        *sfConfig,
		CloudStorage:        *cloud,
		SubdomainBruteforce: *brute,
		SubdomainWordlist:   *wordlist,
	}
	if *skip != "" {
		if err := p.ApplySkips(splitComma(*skip)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}
	if err := p.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
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

	if outFile == "" {
		if err := output.Render(os.Stdout, res, outFormat); err != nil {
			fmt.Fprintln(os.Stderr, "error: writing output:", err)
			return 1
		}
		return 0
	}
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot create output file:", err)
		return 1
	}
	err = output.Render(f, res, outFormat)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: writing output:", err)
		return 1
	}
	if !*quiet {
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
