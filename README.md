# surface

How exposed are you? And do you want to find out?

## CLI

```shell
└─$ surface --help
surface — attack surface discovery

Usage:
  surface scan [--json] [--ports] [--quiet] <domain>
  surface version

Flags:
  --json    output JSON instead of a text report
  --ports   also run the port-scan stage (slower)
  --quiet   suppress progress logging on stderr

Advanced tuning is read from the environment (all optional):
  IPINFO_TOKEN              ipinfo.io API token
  SUBFINDER_PROVIDER_CONFIG subfinder provider-config.yaml with API keys
                            (defaults to subfinder's own ~/.config path)
  DNS_RESOLVERS             comma-separated, e.g. udp:1.1.1.1:53
  SUBFINDER_MAX_TIME        subfinder cap, e.g. 10m
  PORT_SCAN_TYPE            syn | connect (default connect)
  PORT_SCAN_PORTS           -, 1-1000, 80,443 (default -)
  PORT_SCAN_RATE            packets/sec
```

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

The `scan` tool takes `{ "domain": "example.com", "ports": true, ... }` (same
options as the CLI flags) and returns the full result as JSON text. Quick
manual check:

```sh
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | ./bin/surface-mcp
```

## API

```go
import "surface/asm"

scanner := asm.New(asm.Options{PortScan: true, PortScanType: "connect"})
res, err := scanner.Run(ctx, asm.Target{Domain: "example.com"}, nil)
// res.Subdomains, res.DNSRecords, res.IPInfo, res.PortScans, res.TLSCerts
```

`asm.Compare(prev, cur)` diffs two results (used by surface-cloud to show what
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

MIT.
