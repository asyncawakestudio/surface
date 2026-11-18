# surface

How exposed are you?

> Only scan domains you own or are authorized to test. See
> [Disclaimer](#disclaimer).

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

### Services (`--services`)

Identifies what runs on each open port: name, product, version, TLS, banner
and CPEs (CPE 2.3, the identifiers vulnerability databases use).

- **Requires** `--ports` and nmap's `nmap-service-probes` file, from a local
  nmap install (`apt install nmap`, `brew install nmap`) or `--service-probes`.
  Not bundled: it is under nmap's license. The scan stops at the start if it
  is missing.
- **Intrusive:** sends protocol probes to every open port, not just a
  connection attempt.

### Vulnerabilities (`--vulns`)

Lists the CVEs affecting each detected service's version, known-exploited
first.

| Step | Source | Gives |
|------|--------|-------|
| Match | [NVD](https://nvd.nist.gov/developers/vulnerabilities) | CVEs whose affected version ranges include the service's versioned CPE; CVSS severity |
| Enrich | [vulnx](https://github.com/projectdiscovery/vulnx) | CISA KEV, EPSS, public PoCs, Nuclei template coverage |

- **Requires** `--services`. Services without a versioned CPE are skipped.
- **Keys (optional):** NVD allows 5 requests per 30s without a key, 50 with
  one ([request a key](https://nvd.nist.gov/developers/request-an-api-key));
  use `--nvd-api-key` or `NVD_API_KEY`. vulnx takes a ProjectDiscovery Cloud
  key via `--pdcp-api-key` or `PDCP_API_KEY`.
- **Version-based:** distributions backport fixes without changing the
  upstream version (e.g. `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`), so check listed
  CVEs against your distribution's advisories.
- If vulnx fails for a CVE, it is still listed, without exploitation data.

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

## Disclaimer

surface is for authorized security testing, such as assessing systems you own
or have written permission to test. Scanning systems without permission may be
illegal where you or the target are.

You are solely responsible for how you use it. It is provided "as is", without
warranty of any kind, and its authors and contributors are not liable for any
misuse, damage or legal consequences arising from its use (see the
[license](LICENSE)). Results, including vulnerability matches, may be
incomplete or wrong; verify them before acting on them.

## License

[MIT](LICENSE).
