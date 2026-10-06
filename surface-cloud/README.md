# surface-cloud

The web product built on top of the [`surface`](../surface) discovery engine:
a Go API that persists scans in Postgres and a React dashboard to drive and
review them. It imports the core engine directly as a Go module
(`replace surface => ../../surface`), so it runs the exact same scans the CLI
and MCP server do.

```
server/      Go API — module `surface-cloud` (imports surface/asm)
  cmd/server/            entrypoint: config, wiring, graceful shutdown
  internal/api/          HTTP handlers + background job runner
  internal/store/        Postgres persistence (pgx) + embedded SQL migrations
  .air.toml              hot-reload config
client/      React + TypeScript + Tailwind dashboard (Vite)
devops/      Dockerfiles, compose files, subfinder config
  server.Dockerfile      dev (air) + prod (distroless server + built client)
  client.Dockerfile      Vite dev server (development only)
  compose.yaml           dev stack (Postgres + API + Vite, connect port scan)
  compose.prod.yaml      prod stack (host networking, SYN port scan)
```

Both Docker builds use the **repository root** as their context so the image
can see both this module and the sibling `surface/` core module.

## Quick start (development)

```sh
make dev            # docker compose up --build
```

| Service | URL | Notes |
|---------|-----|-------|
| UI | http://localhost:5173 | Vite + React + Tailwind, HMR |
| API | http://localhost:8080 | Go, rebuilt by [air](https://github.com/air-verse/air) on change |
| DB | localhost:5432 | `surface` / `surface`, `make psql` |

The first `make dev` takes a few minutes while Go compiles the ProjectDiscovery
dependencies; the client waits until the server is healthy. The container
bind-mounts both `../surface` (core) and `server/` so the module `replace`
resolves. Editing the cloud server hot-reloads via air; editing the core engine
(`../surface/asm`) needs a server restart.

## Production

```sh
make prod           # distroless server + built UI on http://localhost:8080
```

`compose.prod.yaml` runs the server with host networking so the naabu SYN scan
works (see the port-scanning notes). Set `POSTGRES_PASSWORD` to override the
default.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Start a scan: `{"domain":"example.com"}` → `202`, `409` if one is already in progress for that domain |
| GET | `/api/scans?domain=&limit=` | Scans with result counts, newest first |
| GET | `/api/scans/{id}` | A scan with subdomains, DNS, IP info, ports, TLS |
| GET | `/api/scans/{id}/diff` | Changes vs the domain's previous completed scan |
| POST | `/api/scans/{id}/pause` | Stop a queued/running scan (kept as `paused`) |
| GET | `/api/domains` | Each scanned domain with its latest scan |
| GET | `/healthz` | Liveness + DB check |

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `DATABASE_URL` | — | Postgres connection string (required) |
| `PORT` | `8080` | API listen port |
| `MAX_CONCURRENT_SCANS` | `2` | Scans running at once; the rest queue |
| `SCAN_TIMEOUT_MINUTES` | `30` | Hard limit per scan |
| `SUBFINDER_PROVIDER_CONFIG` | — | Path to subfinder API keys |
| `IPINFO_TOKEN` | — | ipinfo.io API token |
| `DNS_RESOLVERS` | — | Comma-separated resolvers |
| `PORT_SCAN` | `true` | Run the port-scan stage |
| `PORT_SCAN_TYPE` | `syn` | `syn` or `connect`; dev compose uses `connect`, prod uses `syn` (host networking) |
| `PORT_SCAN_RATE` | `5000` | Packets/sec |
| `PORT_SCAN_RETRIES` | `2` | Retry passes |
| `PORT_SCAN_PORTS` | `-` | Port spec (`-` = all 65535) |
| `STATIC_DIR` | — | Serve the built client from this dir (set in the prod image) |

See [`../surface`](../surface) for the engine, CLI, and MCP server.

## Make targets

| Target | Does |
|--------|------|
| `make dev` | dev stack (Postgres + API + Vite) via compose |
| `make down` | stop the dev stack |
| `make prod` / `make prod-down` | prod stack up/down |
| `make logs` | follow the server logs |
| `make psql` | psql into the dev database |
| `make test` | server `go test -race` + client typecheck |
| `make client-build` | build the React bundle |
