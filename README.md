# surface

How exposed are you?

Surface is an attack surface management tool. Give it a domain and it:

1. **Enumerates subdomains** with [subfinder](https://github.com/projectdiscovery/subfinder) (passive sources)
2. **Resolves DNS** with [dnsx](https://github.com/projectdiscovery/dnsx): A, AAAA, CNAME, MX, NS, TXT and CAA
3. **Grabs TLS certificates** with [tlsx](https://github.com/projectdiscovery/tlsx) from every resolved host on :443

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
res, err := scanner.Run(ctx, "example.com", func(s asm.Stage) { log.Println("stage:", s) })
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

Scans run in the background. Poll `GET /api/scans/{id}` until `status` is `completed`, `failed` or `paused`. While running, `stage` is `subdomains`, `dns` or `tls`.

Scans are never deleted: each domain keeps its full history. To rescan a domain, POST it again. The diff compares subdomains by host, DNS records by host+type+value, and certificates by `host:port`. A certificate with a new fingerprint counts as replaced. The tools can't resume partway through a stage, so a paused scan is continued by starting a new one.

## Database

| Table              | Contents                                        |
|--------------------|-------------------------------------------------|
| `scans`            | one row per scan: domain, status, stage, timing. At most one queued/running scan per domain (partial unique index) |
| `subdomains`       | host + the passive sources that reported it     |
| `dns_records`      | host, record type, value                        |
| `tls_certificates` | subject, SANs, issuer, validity, flags, SHA-256 |

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
| `STATIC_DIR`                | —       | Serve the built client from this directory (set in the prod image) |

Without API keys, subfinder uses only free sources. To add keys, copy `devops/config/subfinder/provider-config.example.yaml` to `provider-config.yaml` in the same folder. Compose mounts `devops/config` into the API container.

## Roadmap

- Port scanning (naabu) and service enumeration. These slot into `asm.Scanner.Run` after the DNS stage and will feed discovered ports into the TLS stage.
