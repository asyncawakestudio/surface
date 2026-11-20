# Strip debug info and local paths, as release builds do (~22% smaller).
GOFLAGS ?= -trimpath
LDFLAGS ?= -s -w
DOMAIN  ?= example.com

.PHONY: build install test test-integration run clean fmt vet update-fingerprints

build: ## Build ./bin/surface (CLI and MCP server)
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/surface ./cmd/surface

install: ## go install surface onto your PATH
	go install $(GOFLAGS) -ldflags="$(LDFLAGS)" ./cmd/surface

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

# Refresh the subdomain takeover fingerprints (see asm/data/README.md).
update-fingerprints:
	curl -fsSL -o asm/data/takeover-fingerprints.json \
		https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json
