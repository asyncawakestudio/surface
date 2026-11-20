# surface

[![Downloads](https://img.shields.io/github/downloads/asyncawakestudio/surface/total)](https://github.com/asyncawakestudio/surface/releases)

How exposed are you?

> Only scan domains you own or are authorized to test. See
> [Disclaimer](#disclaimer).

## Install

Download `surface` and `surface-mcp` for your platform from
[Releases](https://github.com/asyncawakestudio/surface/releases), or build
from source (Go 1.27.3+; older Go versions download it automatically):

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

By default these stages run: subdomains, dns, ipdr, cloud, misconfig, web,
certs. The port scan is opt-in (--ports) since it probes every IP the domain
resolves to, including hosting and CDN infrastructure you may not own.

Output:
  --output <dest>       where/how to write results (default: txt to stdout).
                        A file path picks the format by extension
                        (report.json, hosts.csv, out.xml, scan.txt); a bare
                        format name (json, csv, xml, txt) writes to stdout.
  --skip <stages>       comma-separated stages to skip: ipdr, cloud,
                        misconfig, web, certs
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
```

The `syn` port scan sends raw packets, so it needs root (or `CAP_NET_RAW`)
and libpcap installed at runtime (`apt install libpcap0.8`, preinstalled on
macOS). `connect` needs neither.

### Subdomains

Collected from passive sources with
[subfinder](https://github.com/projectdiscovery/subfinder) (certificate
transparency, VirusTotal, Chaos...). With `--subdomain-brute-force`, each
label of a wordlist is then tried as `<label>.<domain>` and kept if it
resolves; those names have source `bruteforce`.

- **Wordlist:** SecLists' top 5,000 subdomains by default (built in, MIT);
  pick another with `--subdomain-wordlist <file>`, one label per line.
- **Wildcard DNS:** random names are resolved first; a guess whose answer
  matches theirs is dropped, since under a wildcard every name resolves.
- **Opt-in:** one DNS query per label not already found (about 5,000 by
  default).

### Services (`--services`)

Identifies what runs on each open port: name, product, version, TLS, banner
and CPEs (CPE 2.3, the identifiers vulnerability databases use).

- **Requires** `--ports` and nmap's `nmap-service-probes` file, from a local
  nmap install (`apt install nmap`, `brew install nmap`) or `--service-probes`.
  Not bundled: it is under nmap's license. The scan stops at the start if it
  is missing.
- **Intrusive:** sends protocol probes to every open port, not just a
  connection attempt.

### Cloud (on by default)

Shows what runs where and who signs users in. No requests go to the target.

- **Hosts on cloud and edge services:** each host's addresses are matched
  against AWS's published IP ranges (naming the service and region, e.g.
  `AWS EC2 us-east-1`) and other providers' ranges (Azure, Google Cloud,
  Cloudflare, Akamai...), and its CNAME against known services
  (`*.elb.amazonaws.com` → Elastic Load Balancing, `*.azurewebsites.net` →
  App Service, `*.cloudfront.net`, Heroku, Vercel, Netlify...).
- **Identity:** the domain's Microsoft Entra ID tenant from Microsoft's
  public sign-in endpoints: tenant ID and region, whether sign-in is managed
  or federated (and the federation server, e.g. ADFS), and the other domains
  verified in the tenant, as far as Microsoft discloses them. Google
  Workspace is detected from MX records.
- **`--cloud-services`** (opt-in) guesses resources named after the domain
  (`example`, `example-dev`, `examplecom`...) and keeps those whose DNS name
  exists: Azure App Service, Key Vault, SQL Database, Container Registry,
  Cosmos DB, API Management, Service Bus, Redis, SharePoint, Google App
  Engine and Firebase, plus Okta orgs. About 300 DNS queries; services with
  wildcard DNS are skipped. A match may belong to someone else.
- Turn it off with `--skip cloud`.

### Misconfigurations (on by default)

Flags DNS, email and TLS settings that let others spoof the domain's mail,
read its DNS, take over its subdomains or weaken its encrypted connections.
Findings are listed most severe first.

| Check | Flags |
|-------|-------|
| `takeover` | A subdomain whose CNAME points at a third-party resource nobody owns any more (a deleted S3 bucket, Azure app...), which someone else could claim. **High** when the service is known to allow takeovers and its "unclaimed" sign matched: the target doesn't exist, or the page shows the service's error (e.g. `The specified bucket does not exist`). **Medium** when the target doesn't exist and matches no known service. |
| `zone_transfer` | A nameserver that hands its whole zone to anyone (AXFR, high). |
| `spf` | No SPF record, several records, `+all` (anyone may send, high), `?all` or no `all` (spoofed mail isn't rejected). Run on the root domain and every subdomain with MX records. |
| `dmarc` | No DMARC record on the root domain, several records, `p=none` or no policy; `sp=none` or `pct` below 100 (low). |
| `caa` | No CAA record: any certificate authority may issue certificates for the domain (low). |
| `tls_version` | An endpoint whose best protocol is SSL 3.0, TLS 1.0 or TLS 1.1. |
| `tls_cipher` | A broken cipher negotiated: RC4, DES/3DES, NULL, export grade, anonymous or MD5 (high). |
| `cert_expired`, `cert_expiring` | A certificate that has expired (high) or expires within 30 days. |
| `cert_self_signed`, `cert_mismatch` | A self-signed certificate, or one that doesn't cover the host. |
| `public_bucket` | With `--cloud-storage`: an AWS S3, Google Cloud Storage or Azure Blob container named after the domain that anyone can list (high). |

- Works from the DNS stage's records. It also sends one AXFR attempt per
  nameserver of the root domain, and HTTP requests only to subdomains whose
  CNAME names a known takeover service, without verifying certificates (an
  unclaimed resource shows the provider's).
- Takeover fingerprints come from
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
  (CC BY 4.0); `make update-fingerprints` refreshes them. Services it lists
  as edge cases, such as GitHub Pages and Heroku, are at most medium.
- The TLS checks use the certificate stage's connections, so they need it
  (`--skip certs` turns them off). It probes port 443 on every host, plus
  ports where the port scan or web stage saw TLS. Only the version and cipher
  each endpoint negotiates are checked, not every one it accepts.
- `--cloud-storage` guesses names from the domain and common words
  (`example-backups`, `static-example`, `examplecom-dev`...): about 250
  anonymous requests to S3, Google Cloud and Azure, plus 10 container
  guesses per Azure account that exists. It reads listings only, never objects. A bucket named after
  you may belong to someone else, so check its owner before acting.
- DKIM isn't checked: its records live under selector names that can't be
  listed, so a missing key can't be told apart from an unknown selector.
- Turn it off with `--skip misconfig`.

### Web (on by default)

Requests each host over HTTPS, falling back to HTTP, with
[httpx](https://github.com/projectdiscovery/httpx) and records the status,
redirect target, title, web server, technologies with versions (Wappalyzer
fingerprints, e.g. `WordPress 6.4.1`) and the CDN or WAF in front of it.

- **Ports:** with `--ports`, every open port that may serve HTTP (ports where
  `--services` found e.g. SSH are skipped); otherwise 80 and 443.
- One row per site: an IP and port often serve several hosts.
- Redirects are not followed, so a `301` shows where it points.
- Turn it off with `--skip web`.

### Vulnerabilities (`--vulns`)

Lists the CVEs affecting each detected service's and web technology's
version, known-exploited first.

| Step | Source | Gives |
|------|--------|-------|
| Match | [NVD](https://nvd.nist.gov/developers/vulnerabilities) | CVEs whose affected version ranges include the service's versioned CPE; CVSS severity |
| Enrich | [vulnx](https://github.com/projectdiscovery/vulnx) | CISA KEV, EPSS, public PoCs, Nuclei template coverage |

- **Works from** `--services` and the web stage; either is enough, so
  `surface --vulns example.com` checks web technologies only. Products
  without a versioned CPE are skipped.
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
// res.CloudAssets, res.Identity: cloud services behind hosts; Entra ID, Google Workspace, Okta
// res.Misconfigurations: weak SPF, DMARC, CAA and zone transfer settings, and
//   subdomains whose CNAME points at an unclaimed resource
// res.Web: what each host serves over HTTP(S), with detected technologies
// res.Vulnerabilities: with VulnLookup, the CVEs affecting each service and technology
```

The engine's own defaults differ from the CLI: `PortScanType` defaults to
`"syn"`. `asm.Compare(prev, cur)` diffs two results (used by surface-cloud to show what
changed between scans): subdomains, DNS records, IP data, certificates, open ports,
service versions, web pages, misconfigurations (including takeover risks), cloud assets,
Entra tenant domains and CVEs. Ports, web pages, misconfigurations, cloud results and
CVEs are only compared when both scans looked for them (`Result.Stages`).

## Building

| Target | Does |
|--------|------|
| `make build` | build `bin/surface` and `bin/surface-mcp` |
| `make install` | `go install` both commands |
| `make test` | `go vet` + unit tests (race) |
| `make test-integration` | live tests (network): `go test -tags integration ./asm` |
| `make run DOMAIN=example.com` | build + scan a domain |

## Disclaimer

**For authorized use only**. This tool is provided for educational and
legitimate security testing purposes. You are solely responsible for obtaining
proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse
or damages.

_Use at your own risk._

## License

[MIT](LICENSE).
