# surface

The core attack-surface **discovery service** — and the two ways to drive it:
a **CLI** for humans and an **MCP server** for AI agents. Both run the same
engine, so a person and a model get identical results.

Give it a domain and it:

1. **Enumerates subdomains** with [subfinder](https://github.com/projectdiscovery/subfinder) (`-all` passive sources)
2. **Resolves DNS** with [dnsx](https://github.com/projectdiscovery/dnsx): A, AAAA, CNAME, MX, NS, TXT, CAA
3. **Looks up every public IP** with [ipinfo.io](https://ipinfo.io) (owner, ASN, geo)
4. **Scans ports** with [naabu](https://github.com/projectdiscovery/naabu) (optional; SYN or connect)
5. **Inspects TLS certificates** with [tlsx](https://github.com/projectdiscovery/tlsx)

The ProjectDiscovery tools are used as Go libraries, not shelled-out binaries.
This module has **no database and no web server** — it computes a result and
returns it. Persistence, the API, and the dashboard live in `../surface-cloud`.

> Only scan domains you own or are authorized to test.

## Layout

```
asm/                 the discovery engine (importable: surface/asm)
  asm.go             Scanner.Run(ctx, Target, progress) -> *Result
  subdomains.go      subfinder stage       dns.go     dnsx stage
  ipinfo.go          ipinfo.io stage       ports.go   naabu stage
  tls.go             tlsx stage            diff.go    scan-to-scan diff
cmd/surface/         CLI (human)
cmd/surface-mcp/     MCP stdio server (AI)
internal/scan/       shared params + option building for both front-ends
```

## CLI (humans)

```sh
make build                            # builds ./bin/surface and ./bin/surface-mcp
./bin/surface example.com                      # full scan, text report to stdout
./bin/surface --output=json example.com        # JSON to stdout
./bin/surface --output=report.csv example.com  # CSV to a file
./bin/surface --skip=tls,ports example.com     # skip stages
```

Just `surface <domain>` runs every stage — subdomains, dns, ipinfo, ports (all
65535), tls. Flags (before the domain):

| Flag | Description |
|------|-------------|
| `--output=<dest>` | where/how to write results. Empty → `txt` to stdout. A bare format (`txt`, `json`, `csv`, `xml`) → that format to stdout. A file path → format from its extension (`report.json`, `hosts.csv`, `out.xml`) |
| `--skip=<stages>` | comma-separated stages to skip: `ipinfo`, `ports`, `tls` (subdomains and dns always run) |
| `--quiet` | no progress on stderr |
| `--ipinfo-token=<tok>` | ipinfo.io API token |
| `--subfinder-config=<f>` | subfinder `provider-config.yaml` with API keys (defaults to subfinder's own `~/.config` path) |
| `--resolvers=<list>` | comma-separated, e.g. `udp:1.1.1.1:53` |
| `--max-time=<dur>` | subfinder enumeration cap, e.g. `10m` |
| `--port-type=<t>` | `syn` or `connect` (default `connect`) |
| `--port-spec=<s>` | `-` (all), `1-1000`, `80,443` |
| `--port-rate=<n>` | packets/sec for the port scan |

The `txt` report is for reading; `json` carries the full nested result; `csv`
and `xml` are flat, one row per finding (`type,host,ip,port,field,value`).

## MCP (AI agents)

`surface-mcp` speaks the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0), exposing one tool, `scan`. Point an MCP client at the binary:

```json
{
  "mcpServers": {
    "surface": { "command": "/path/to/surface-mcp" }
  }
}
```

The `scan` tool takes `{ "domain": "example.com", "ports": true, ... }` (same
options as the CLI flags) and returns the full result as JSON text. Quick
manual check:

```sh
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | ./bin/surface-mcp
```

## As a library

```go
import "surface/asm"

scanner := asm.New(asm.Options{PortScan: true, PortScanType: "connect"})
res, err := scanner.Run(ctx, asm.Target{Domain: "example.com"}, nil)
// res.Subdomains, res.DNSRecords, res.IPInfo, res.PortScans, res.TLSCerts
```

`asm.Compare(prev, cur)` diffs two results (used by surface-cloud to show what
changed between scans).

## Make targets

| Target | Does |
|--------|------|
| `make build` | build `bin/surface` and `bin/surface-mcp` |
| `make install` | `go install` both commands |
| `make test` | `go vet` + unit tests (race) |
| `make test-integration` | live tests (network): `go test -tags integration ./asm` |
| `make run DOMAIN=example.com` | build + scan a domain |
