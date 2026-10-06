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
make build                       # builds ./bin/surface and ./bin/surface-mcp
./bin/surface example.com                 # full scan, text report
./bin/surface --json example.com          # JSON
./bin/surface --skip=tls,ports example.com
```

Just `surface <domain>` runs every stage — subdomains, dns, ipinfo, ports (all
65535), tls. Flags (before the domain):

| Flag | Description |
|------|-------------|
| `--json` | machine-readable JSON instead of a text report |
| `--quiet` | no progress on stderr |
| `--skip=<stages>` | comma-separated stages to skip: `ipinfo`, `ports`, `tls` (subdomains and dns always run) |

Advanced tuning is read from the environment (all optional), matching how
`surface-cloud` is configured:

| Env var | Description |
|---------|-------------|
| `IPINFO_TOKEN` | ipinfo.io API token |
| `SUBFINDER_PROVIDER_CONFIG` | subfinder `provider-config.yaml` with API keys (defaults to subfinder's own `~/.config` path) |
| `DNS_RESOLVERS` | comma-separated, e.g. `udp:1.1.1.1:53` |
| `SUBFINDER_MAX_TIME` | subfinder cap, e.g. `10m` |
| `PORT_SCAN_TYPE` | `syn` or `connect` (default `connect`) |
| `PORT_SCAN_PORTS` | `-` (all), `1-1000`, `80,443` |
| `PORT_SCAN_RATE` | packets/sec |

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
