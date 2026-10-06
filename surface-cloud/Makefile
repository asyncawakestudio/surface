COMPOSE      = docker compose -f devops/compose.yaml
COMPOSE_PROD = docker compose -f devops/compose.prod.yaml

.PHONY: dev down prod prod-down logs psql test test-integration client-install client-build server-build

dev: ## Postgres + API (air hot reload) + Vite dev server
	$(COMPOSE) up --build

down:
	$(COMPOSE) down

prod: ## Production stack: distroless server (API + built client), SYN scan
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

# Store tests against a disposable database:
#   TEST_DATABASE_URL=postgres://... make test-integration
test-integration:
	cd server && go test -tags integration -count=1 -v ./internal/store

client-install:
	cd client && npm install

client-build:
	cd client && npm run build

server-build:
	cd server && CGO_ENABLED=0 go build -o bin/server ./cmd/server
