// Command surface is the human-facing CLI for the core discovery service.
//
//	surface example.com                 # scan, human-readable report
//	surface --output=json example.com   # machine-readable JSON
//	surface --ports --skip=certs example.com
//	surface --ports --services example.com
//	surface --ports --services --vulns example.com
//	surface --vulns example.com         # CVEs for web technologies only
//	surface mcp                         # MCP server on stdio
//
// It runs the same engine as the cloud product.
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
	"github.com/asyncawakestudio/surface/internal/mcp"
	"github.com/asyncawakestudio/surface/internal/output"
	"github.com/asyncawakestudio/surface/internal/scan"
	"github.com/asyncawakestudio/surface/internal/termui"
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
	case "mcp":
		if err := mcp.Serve(os.Stdin, os.Stdout, version); err != nil {
			fail("surface mcp: %v", err)
			os.Exit(1)
		}
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
  surface mcp           run as an MCP server on stdio
  surface version

By default these stages run: subdomains, dns, ipdr, cloud, web, certs.
The port scan is opt-in (--ports) since it probes every IP the domain
resolves to, including hosting and CDN infrastructure you may not own.

Output:
  --output <dest>       where/how to write results (default: txt to stdout).
                        A file path picks the format by extension
                        (report.json, hosts.csv, out.xml, scan.txt); a bare
                        format name (json, csv, xml, txt) writes to stdout.
  --skip <stages>       comma-separated stages to skip: ipdr, cloud, web,
                        certs
                        (subdomains and dns are always run)
  --subdomain-brute-force
                        after subfinder, also try each label of a wordlist
                        as <label>.<domain> (one DNS query per label)
  --cloud-storage       also look for public AWS S3, Google Cloud and Azure
                        buckets named after the domain (guesses names)
  --cloud-services      also look for Azure, Google Cloud, Microsoft 365 and
                        Okta resources named after the domain (guesses names)
  --ports               also run the port scan (all 65535 TCP ports by default)
                        (not available in Windows ARM64 builds)
  --services            with --ports, identify the service on each open port
                        (product, version, CPEs) using nmap's service probes;
                        needs nmap installed or --service-probes
  --vulns               look up the CVEs affecting each detected service's
                        and web technology's version (NVD), with exploitation
                        data from ProjectDiscovery's vulnx (KEV, EPSS, PoCs)
  --quiet               suppress the banner and progress logging on stderr
  --no-color            don't colour the output (also: NO_COLOR=1); output
                        that isn't a terminal is never coloured

Tuning (all optional):
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

API keys, from the environment only (all optional):
  <SOURCE>_API_KEY          subdomain sources, e.g. VIRUSTOTAL_API_KEY,
                            SHODAN_API_KEY (or --subfinder-config)
  IPINFO_TOKEN              ipinfo.io
  NVD_API_KEY               NVD, for --vulns: 10x higher rate limit
  PDCP_API_KEY              ProjectDiscovery Cloud, for --vulns
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	var (
		outDest   = fs.String("output", "", "output destination: a file path (format by extension) or a format name; empty = txt to stdout")
		skip      = fs.String("skip", "", "comma-separated stages to skip: ipdr, cloud, web, certs")
		ports     = fs.Bool("ports", false, "also run the port scan")
		quiet     = fs.Bool("quiet", false, "suppress progress logging on stderr")
		noColor   = fs.Bool("no-color", false, "don't colour the output")
		sfConfig  = fs.String("subfinder-config", "", "subfinder provider-config.yaml")
		cloud     = fs.Bool("cloud-storage", false, "look for public cloud storage buckets named after the domain")
		cloudSvcs = fs.Bool("cloud-services", false, "look for cloud resources named after the domain")
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
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fail("exactly one <domain> is required (put flags before the domain)")
		usage()
		return 2
	}
	outFormat, outFile, err := resolveOutput(*outDest)
	if err != nil {
		fail("%v", err)
		return 2
	}

	if !*ports && (*portType != "" || *portSpec != "" || *portRate != 0 || *services) {
		fail("--port-type, --port-spec, --port-rate and --services require --ports")
		return 2
	}
	if !*services && *probes != "" {
		fail("--service-probes requires --services")
		return 2
	}

	p := scan.Params{
		Domain:        rest[0],
		Ports:         *ports,
		PortType:      *portType,
		PortSpec:      *portSpec,
		PortRate:      *portRate,
		Services:      *services,
		ServiceProbes: *probes,
		Vulns:         *vulns,
		// API keys come from the environment only: flags would show them in
		// ps and shell history.
		NVDAPIKey:           os.Getenv("NVD_API_KEY"),
		PDCPAPIKey:          os.Getenv("PDCP_API_KEY"),
		IPInfoToken:         os.Getenv("IPINFO_TOKEN"),
		SubfinderCfg:        *sfConfig,
		CloudStorage:        *cloud,
		CloudServices:       *cloudSvcs,
		SubdomainBruteforce: *brute,
		SubdomainWordlist:   *wordlist,
	}
	if *skip != "" {
		if err := p.ApplySkips(splitComma(*skip)); err != nil {
			fail("%v", err)
			return 2
		}
	}
	if err := p.Validate(); err != nil {
		fail("%v", err)
		return 2
	}
	if *resolvers != "" {
		p.Resolvers = splitComma(*resolvers)
	}
	if *maxTime != "" {
		d, err := time.ParseDuration(*maxTime)
		if err != nil {
			fail("invalid --max-time: %v", err)
			return 2
		}
		p.MaxTime = d
	}

	if *noColor {
		errColor = false
	}
	stderr := termui.Palette{On: errColor}
	var logs *slog.Logger
	if !*quiet {
		termui.PrintBanner(os.Stderr, stderr, version)
		logs = slog.New(termui.NewHandler(os.Stderr, stderr, slog.LevelInfo))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	progress := func(stage asm.Stage) {
		if logs != nil {
			msg := stageMessages[stage]
			if msg == "" {
				msg = "Running " + string(stage)
			}
			logs.Info(msg + " for " + rest[0])
		}
	}

	start := time.Now()
	res, err := scan.Run(ctx, p, logs, progress)
	if err != nil {
		fail("scan failed: %v", err)
		return 1
	}
	if logs != nil {
		logs.Info(fmt.Sprintf("Found %s in %s", summary(res), time.Since(start).Round(time.Second)))
	}

	if outFile == "" {
		opts := output.Options{Color: !*noColor && termui.ColorFor(os.Stdout)}
		if err := output.RenderWith(os.Stdout, res, outFormat, opts); err != nil {
			fail("writing output: %v", err)
			return 1
		}
		return 0
	}
	f, err := os.Create(outFile)
	if err != nil {
		fail("cannot create output file: %v", err)
		return 1
	}
	err = output.Render(f, res, outFormat)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fail("writing output: %v", err)
		return 1
	}
	if logs != nil {
		logs.Info(fmt.Sprintf("Wrote %s output to %s", outFormat, outFile))
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

// errColor is whether [ERR] lines on stderr are coloured.
var errColor = termui.ColorFor(os.Stderr)

// fail prints an error as an [ERR] line on stderr.
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", termui.Label(termui.Palette{On: errColor}, slog.LevelError), fmt.Sprintf(format, a...))
}

// stageMessages describe each stage as it starts.
var stageMessages = map[asm.Stage]string{
	asm.StageSubdomains: "Enumerating subdomains",
	asm.StageDNS:        "Resolving DNS records",
	asm.StageIPDR:       "Looking up IP ownership",
	asm.StageCloud:      "Discovering cloud services and identity providers",
	asm.StagePorts:      "Scanning ports",
	asm.StageWeb:        "Probing web servers",
	asm.StageVulns:      "Looking up vulnerabilities",
	asm.StageCerts:      "Collecting TLS certificates",
}

// summary counts what a scan found, e.g. "12 subdomains, 40 DNS records".
func summary(r *asm.Result) string {
	ports := 0
	for _, ps := range r.PortScans {
		ports += len(ps.Ports)
	}
	cves := 0
	for _, sv := range r.Vulnerabilities {
		cves += len(sv.Vulnerabilities)
	}
	counts := []struct {
		n    int
		what string
		show bool
	}{
		{len(r.Subdomains), "subdomains", true},
		{len(r.DNSRecords), "DNS records", true},
		{len(r.ZoneTransfers), "zone transfers", len(r.ZoneTransfers) > 0},
		{len(r.CloudAssets), "cloud assets", slices.Contains(r.Stages, asm.StageCloud)},
		{len(r.PublicBuckets), "public buckets", slices.Contains(r.Stages, asm.StageCloudStorage)},
		{ports, "open ports", slices.Contains(r.Stages, asm.StagePorts)},
		{len(r.Web), "web pages", slices.Contains(r.Stages, asm.StageWeb)},
		{cves, "CVEs", slices.Contains(r.Stages, asm.StageVulns)},
		{len(r.TLSCerts), "certificates", slices.Contains(r.Stages, asm.StageCerts)},
	}
	var parts []string
	for _, c := range counts {
		if c.show {
			what := c.what
			if c.n == 1 {
				what = strings.TrimSuffix(what, "s")
			}
			parts = append(parts, fmt.Sprintf("%d %s", c.n, what))
		}
	}
	return strings.Join(parts, ", ")
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
