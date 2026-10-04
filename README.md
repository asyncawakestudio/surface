# surface

How exposed are you?

Surface is an attack surface management tool. Give it a domain and it:

1. **Enumerates subdomains** with [subfinder](https://github.com/projectdiscovery/subfinder) (passive sources)
2. **Resolves DNS** with [dnsx](https://github.com/projectdiscovery/dnsx): A, AAAA, CNAME, MX, NS, TXT and CAA
3. **Looks up every public IP** with [ipinfo.io](https://ipinfo.io) (IPDR: owner, ASN, location, etc.)
4. **Scans ports** with [naabu](https://github.com/projectdiscovery/naabu): a half-open SYN scan of all TCP ports on each IPv4 address
5. **Grabs TLS certificates** with [tlsx](https://github.com/projectdiscovery/tlsx) from every resolved host on :443

The ProjectDiscovery tools are used as Go libraries, not shelled-out binaries. Results are stored in Postgres and shown on a React dashboard.

> Only scan domains you own or are authorized to test. TLS probing connects directly to the target hosts.

## Quick start (development)

```sh
make dev   # docker compose -f devops/compose.yaml up --build
```

| Service | URL                   | Notes                                     |
|---------|-----------------------|-------------------------------------------|
| UI      | http://localhost:5173 | Vite + React + Tailwind, HMR              |
| API     | http://localhost:8080 | Go, rebuilt by [air](https://github.com/air-verse/air) on change |
| DB      | localhost:5432        | `surface` / `surface`, `make psql`        |

The first `make dev` takes a few minutes while Go compiles the ProjectDiscovery dependencies. The client container waits until the server is healthy. Later runs reuse the cached modules and builds. Edit Go code and air rebuilds the API. Edit anything in `client/src` and Vite hot-reloads the page. After changing `client/package.json`, run `docker compose -f devops/compose.yaml up --build -V` so the container's `node_modules` volume is recreated.

## Production

```sh
make prod  # one distroless container serving the API and the built UI on http://localhost:8080
```

Set `POSTGRES_PASSWORD` in the environment to override the default password.

## Layout

```
server/                   Go API
  cmd/server/             entrypoint: config, wiring, graceful shutdown
  internal/asm/           scan pipeline: Scanner.Run(ctx, domain, progress)
    subdomains.go         subfinder stage
    dns.go                dnsx stage
    ipinfo.go             ipinfo.io stage (IPDR)
    ports.go              naabu port-scan stage
    tls.go                tlsx stage
  internal/store/         Postgres persistence (pgx) + embedded SQL migrations
  internal/api/           HTTP handlers and background job runner
  .air.toml               hot reload config
client/                   React + TypeScript + Tailwind dashboard (Vite)
devops/
  server.Dockerfile       dev target (air); prod target = distroless server + built client
  client.Dockerfile       Vite dev server (development only)
  *.Dockerfile.dockerignore
  compose.yaml            development stack
  compose.prod.yaml       production stack
  config/subfinder/       subfinder provider (API key) config
```

Both Dockerfiles use the repository root as their build context. Each one has its own `<name>.Dockerfile.dockerignore`, which limits what gets sent into the build.

### Using the scanner as a library

```go
scanner := asm.New(asm.Options{})
res, err := scanner.Run(ctx, asm.Target{
    Domain:          "example.com",
    KnownSubdomains: previous, // optional: subdomains from earlier scans, kept even if not found again
}, func(s asm.Stage) { log.Println("stage:", s) })
// res.Subdomains, res.DNSRecords, res.TLSCerts
```

## API

| Method | Path                   | Description                                                   |
|--------|------------------------|---------------------------------------------------------------|
| POST   | `/api/scans`           | Start a scan: `{"domain": "example.com"}` → `202`, or `409` if that domain already has a scan in progress |
| GET    | `/api/scans`           | Scans with result counts, newest first (`?domain=`, `?limit=`) |
| GET    | `/api/scans/{id}`      | A scan with its subdomains, DNS records and certificates       |
| GET    | `/api/scans/{id}/diff` | Changes since the domain's previous completed scan (`base` is `null` for the first one) |
| POST   | `/api/scans/{id}/pause`| Stop a queued or running scan; it's kept as `paused`           |
| GET    | `/api/domains`         | Every scanned domain with its latest scan and scan count       |
| GET    | `/healthz`             | Liveness + DB check                                           |

Scans run in the background. Poll `GET /api/scans/{id}` until `status` is `completed`, `failed` or `paused`. While running, `stage` is `subdomains`, `dns`, `ipinfo`, `ports` or `tls`.

Scans are never deleted: each domain keeps its full history.

Subdomains are append-only. Each scan starts with every subdomain found by the domain's earlier completed scans, then adds whatever subfinder finds now. Hosts that no source reported this time are kept with `carried_over: true` and the sources that reported them before. They still go through DNS and TLS, so a host that stopped resolving shows up as unresolved instead of vanishing. Because a subdomain never disappears, the diff reports `no_longer_reported` (found by sources last scan, carried over now) instead of `removed`. To rescan a domain, POST it again. The diff compares subdomains by host, DNS records by host+type+value, and certificates by `host:port`. A certificate with a new fingerprint counts as replaced. IPDR data is compared by IP: new and gone IPs, plus every ipinfo field whose value changed for an IP in both scans (e.g. `org` or `asn.asn` when an IP changes owner). Failed lookups are never compared. If the previous scan ran before IP lookups existed, `ip_info.compared` is `false` instead of listing every IP as new. The tools can't resume partway through a stage, so a paused scan is continued by starting a new one.

## Database

| Table              | Contents                                        |
|--------------------|-------------------------------------------------|
| `scans`            | one row per scan: domain, status, stage, timing. At most one queued/running scan per domain (partial unique index) |
| `subdomains`       | host, the passive sources that reported it, and `carried_over` |
| `dns_records`      | host, record type, value                        |
| `tls_certificates` | subject, SANs, issuer, validity, flags, SHA-256 |
| `ip_info`          | IPDR: the raw ipinfo.io JSON response per public IP (JSONB), or the lookup error |
| `port_scan_targets`| one row per scanned IPv4 address, with the hosts that resolved to it |
| `open_ports`       | one row per open port found (ip, port, protocol) |

Migrations in `server/internal/store/migrations` are embedded and applied once each at startup; applied versions are tracked in `schema_migrations`.

## Configuration

| Env var                     | Default | Description                               |
|-----------------------------|---------|-------------------------------------------|
| `DATABASE_URL`              | —       | Postgres connection string (required)     |
| `PORT`                      | `8080`  | API listen port                           |
| `MAX_CONCURRENT_SCANS`      | `2`     | Scans that run at once; the rest queue    |
| `SCAN_TIMEOUT_MINUTES`      | `30`    | Hard limit per scan                       |
| `SUBFINDER_PROVIDER_CONFIG` | —       | Path to subfinder API keys (see below)    |
| `DNS_RESOLVERS`             | —       | Comma-separated resolvers, e.g. `udp:1.1.1.1:53,tcp:8.8.8.8:53`. When unset, dnsx's public resolvers are used, falling back to the system resolver if they're unreachable |
| `IPINFO_TOKEN`              | —       | ipinfo.io API token. Optional; without it the free tier's lower rate limits apply. Compose reads it from your shell or `devops/.env` |
| `PORT_SCAN`                 | `true`  | Run the naabu port-scan stage. A half-open SYN scan needs the `NET_RAW` capability (compose grants it); otherwise naabu falls back to a TCP connect scan |
| `STATIC_DIR`                | —       | Serve the built client from this directory (set in the prod image) |

Only globally routable IPs are sent to ipinfo.io: private, loopback, CGNAT and documentation ranges are skipped. A failed lookup (e.g. HTTP 429 when rate limited) is recorded on that IP and doesn't fail the scan. The IPDR tab builds its columns from whatever fields the response contains, so paid-plan fields such as `asn`, `company` or `privacy` show up automatically (flattened as `asn.name` etc.), and each row expands to the raw JSON.

The port-scan stage runs a half-open SYN scan (naabu) of all 65535 TCP ports on each **IPv4** address the DNS stage resolved; IPv6 is skipped. A SYN scan sends raw packets, so the container is granted the `NET_RAW` and `NET_ADMIN` capabilities in `devops/compose.yaml`; without them naabu automatically falls back to a slower TCP connect scan. naabu loads `libpcap` at runtime, so both the dev (Alpine) and prod (distroless) images ship it. Set `PORT_SCAN=false` to skip the stage. Only scan hosts you are authorized to test.

Without API keys, subfinder uses only free sources. To add keys, copy `devops/config/subfinder/provider-config.example.yaml` to `provider-config.yaml` in the same folder. Compose mounts `devops/config` into the API container.

## Roadmap

- Port scanning (naabu) and service enumeration. These slot into `asm.Scanner.Run` after the DNS stage and will feed discovered ports into the TLS stage.
