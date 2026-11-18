# surface

How exposed are you? And do you want to find out?

> Only scan domains you own or are authorized to test.

## Install

Download `surface` and `surface-mcp` for your platform from
[Releases](https://github.com/asyncawakestudio/surface/releases), or build
from source (Go 1.26+):

```sh
go install github.com/asyncawakestudio/surface/cmd/surface@latest
go install github.com/asyncawakestudio/surface/cmd/surface-mcp@latest
```

## CLI

```shell
└─$ ./bin/surface --help
surface — attack surface discovery

Usage:
  surface [flags] <domain>
  surface version

By default these stages run: subdomains, dns, ipdr, certs. The port scan is
opt-in (--ports) since it probes every IP the domain resolves to, including
hosting and CDN infrastructure you may not own.

Output:
  --output <dest>       where/how to write results (default: txt to stdout).
                        A file path picks the format by extension
                        (report.json, hosts.csv, out.xml, scan.txt); a bare
                        format name (json, csv, xml, txt) writes to stdout.
  --skip <stages>       comma-separated stages to skip: ipdr, certs
                        (subdomains and dns are always run)
  --ports               also run the port scan (all 65535 TCP ports by default)
  --services            with --ports, identify the service on each open port
                        (product, version, CPEs) using nmap's service probes;
                        needs nmap installed or --service-probes
  --vulns               with --services, look up the CVEs affecting each
                        detected service's version (NVD), with exploitation
                        data from ProjectDiscovery's vulnx (KEV, EPSS, PoCs)
  --quiet               suppress progress logging on stderr

Tuning (all optional):
  --ipinfo-token <tok>      ipinfo.io API token
  --subfinder-config <f>    subfinder provider-config.yaml with API keys
                            (defaults to subfinder's own ~/.config path)
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
```

The `syn` port scan sends raw packets, so it needs root (or `CAP_NET_RAW`)
and libpcap installed at runtime (`apt install libpcap0.8`, preinstalled on
macOS). `connect` needs neither.

`--services` sends protocol probes to every open port, not just a connection
attempt, so it is opt-in on top of `--ports`. It reads nmap's
`nmap-service-probes` file from a local nmap installation
(`apt install nmap`, `brew install nmap`) or from `--service-probes`; surface
doesn't ship it, since it is covered by nmap's own license. The scan stops at
the start if the file can't be found. Each identified port gets a `service`
with its CPEs in CPE 2.3 form, the identifiers vulnerability databases use.

`--vulns` looks up the CVEs affecting each detected service's version. NVD
matches the service's versioned CPE against each CVE's affected version
ranges; [vulnx](https://github.com/projectdiscovery/vulnx) then adds whether
it is known exploited (CISA KEV), its EPSS score, public PoCs and Nuclei
template coverage. Known-exploited CVEs are listed first. Both APIs work
without keys, but NVD allows only 5 requests per 30 seconds without one
([request a key](https://nvd.nist.gov/developers/request-an-api-key)), so a
scan with many distinct service versions is slow. Matching is by version
only: Linux distributions often backport fixes without changing the upstream
version (e.g. `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`), so check listed CVEs
against your distribution's advisories.

## MCP

`surface-mcp` speaks the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0), exposing one tool, `scan`. Point an MCP client at the binary:

```json
{
  "mcpServers": {
    "surface": { "command": "/path/to/surface-mcp" }
  }
}
```

The `scan` tool takes `{ "domain": "example.com", "ports": true, "services": true, "vulns": true, ... }` (same
options as the CLI flags; API keys come from the server's `NVD_API_KEY` and
`PDCP_API_KEY` environment variables) and returns the full result as JSON text. Scans run
concurrently and stop on `notifications/cancelled`. Quick manual check:

```sh
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | ./bin/surface-mcp
```

## API

```go
import "github.com/asyncawakestudio/surface/asm"

scanner := asm.New(asm.Options{PortScan: true, PortScanType: "connect", ServiceDetection: true})
res, err := scanner.Run(ctx, asm.Target{Domain: "example.com"}, nil)
// res.Subdomains, res.DNSRecords, res.IPInfo, res.PortScans, res.TLSCerts
// res.Services(): every identified service with its IP, hosts and port
// res.Vulnerabilities: with VulnLookup, the CVEs affecting each service
```

The engine's own defaults differ from the CLI: `PortScanType` defaults to
`"syn"`. `asm.Compare(prev, cur)` diffs two results (used by surface-cloud to show what
changed between scans).

## Building

| Target | Does |
|--------|------|
| `make build` | build `bin/surface` and `bin/surface-mcp` |
| `make install` | `go install` both commands |
| `make test` | `go vet` + unit tests (race) |
| `make test-integration` | live tests (network): `go test -tags integration ./asm` |
| `make run DOMAIN=example.com` | build + scan a domain |

## License

[MIT](LICENSE).
