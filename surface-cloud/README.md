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
| GET/POST | `/api/configs` | List or create scan configurations |
| GET/PUT/DELETE | `/api/configs/{id}` | Read, update, or delete a configuration |
| POST | `/api/configs/{id}/run` | Run a configuration now (one scan per domain) |

## Authentication

Access requires signing in with an **email one-time code**. The flow:

1. `POST /api/auth/request {email}` — the server generates a 6-digit code, stores its hash (10-min expiry), and emails it.
2. `POST /api/auth/verify {email, code}` — on success it creates the user if needed, starts a session, and sets an `HttpOnly` session cookie.
3. `GET /api/auth/me` returns the current user; `POST /api/auth/logout` ends the session.

Every `/api` route except `/api/auth/*` and `/healthz` requires a valid session. Codes are attempt-limited (5) and resends are throttled (60s).

Email is sent over **SMTP**, configured entirely via `SMTP_*` env vars, so the provider differs only by configuration:

- **Development:** a Mailtrap/Mailjet sandbox (`devops/.env`). With `SMTP_HOST` empty the server just **logs** the code (`make logs`), so login works with no mail setup.
- **Production:** **ProtonMail** has no public SMTP — run **[Proton Mail Bridge](https://proton.me/mail/bridge)** on the host; it exposes SMTP on `127.0.0.1:1025` (STARTTLS) with a bridge-generated username/password. Point `SMTP_*` at it. (The Bridge must be reachable from the server process; `compose.prod.yaml` uses host networking, so `127.0.0.1` is the host.)

See `devops/.env.example`.

## Scan configurations

Besides ad-hoc **quick scans** (`POST /api/scans`), you can save **scan configurations**: a named set of target domains, a schedule (manual / daily / weekly / monthly at a time in an IANA timezone), and which stages to run (IPDR, ports, certs — subdomains and DNS always run). A built-in scheduler fans each due configuration out to one scan per domain, skipping any domain already being scanned. Configs are editable and are managed from the dashboard's **Configured scans** panel or the `/api/configs` endpoints.

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
| `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/`SMTP_FROM`/`SMTP_TLS` | — | SMTP for login-code email. Empty `SMTP_HOST` logs codes instead of sending (dev). `SMTP_TLS` is `starttls` (default) or `implicit` |
| `COOKIE_SECURE` | `false` | Set `true` in production (HTTPS) so the session cookie is `Secure` |
| `APP_NAME` | `Surface` | Name shown in login emails |

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
