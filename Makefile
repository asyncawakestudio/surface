COMPOSE      = docker compose -f devops/compose.yaml
COMPOSE_PROD = docker compose -f devops/compose.prod.yaml

.PHONY: dev down prod prod-down logs psql test test-integration client-install client-build

dev: ## Postgres + API (air hot reload) + Vite dev server
	$(COMPOSE) up --build

down:
	$(COMPOSE) down

prod: ## Production image: distroless server (API + built client) on :8080
	$(COMPOSE_PROD) up --build -d

prod-down:
	$(COMPOSE_PROD) down

logs:
	$(COMPOSE) logs -f server

psql:
	$(COMPOSE) exec db psql -U surface -d surface

test:
	cd server && go vet ./... && go test -race ./...
	cd client && npm run typecheck

# Live DNS tests, plus store tests when TEST_DATABASE_URL points at a
# disposable database (tables are truncated).
test-integration:
	cd server && go test -tags integration -count=1 -v ./internal/asm ./internal/store

client-install:
	cd client && npm install

client-build:
	cd client && npm run build
