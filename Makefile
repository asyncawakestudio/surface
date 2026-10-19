GOFLAGS ?=
DOMAIN  ?= example.com

.PHONY: build install test test-integration run clean fmt vet

build: ## Build the CLI and MCP binaries into ./bin
	go build $(GOFLAGS) -o bin/surface ./cmd/surface
	go build $(GOFLAGS) -o bin/surface-mcp ./cmd/surface-mcp

install: ## go install both commands onto your PATH
	go install ./cmd/surface
	go install ./cmd/surface-mcp

fmt:
	gofmt -w .

vet:
	go vet ./...

test: ## Vet + unit tests with the race detector
	go vet ./...
	go test -race ./...

# Live tests that hit the network (DNS, ipinfo, a port scan of scanme.nmap.org).
test-integration:
	go test -tags integration -count=1 -v ./asm

run: build ## Build then scan DOMAIN=<domain>
	./bin/surface scan $(DOMAIN)

clean:
	rm -rf bin
