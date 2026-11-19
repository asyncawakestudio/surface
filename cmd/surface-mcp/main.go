// Command surface-mcp exposes the core discovery service to AI clients over
// the Model Context Protocol (MCP) on stdio. It speaks newline-delimited
// JSON-RPC 2.0 — the MCP stdio transport — with no external dependencies.
//
// Tool: scan(domain, ...) runs the discovery pipeline and returns the result
// as JSON text. Scans run concurrently and can be cancelled with
// notifications/cancelled. Configure an MCP client to launch this binary over
// stdio.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"

	"github.com/asyncawakestudio/surface/internal/scan"
)

const (
	protocolVersion = "2024-11-05"
	serverName      = "surface"
)

// serverVersion is set at release time via -ldflags "-X main.serverVersion=...".
var serverVersion = "dev"

func main() {
	// Protocol traffic is on stdout; everything else must go to stderr.
	log.SetOutput(os.Stderr)
	log.SetPrefix("surface-mcp: ")

	srv := &server{out: bufio.NewWriter(os.Stdout)}
	if err := srv.serve(os.Stdin); err != nil && err != io.EOF {
		log.Fatal(err)
	}
}

// --- JSON-RPC 2.0 framing ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError    = -32700
	codeInvalidReq    = -32600
	codeMethodMissing = -32601
	codeInvalidParams = -32602
	codeInternal      = -32603
)

type server struct {
	outMu sync.Mutex // guards out: tool calls reply from their own goroutines
	out   *bufio.Writer

	mu       sync.Mutex
	inflight map[string]context.CancelFunc // by request ID, for cancellation
	wg       sync.WaitGroup
}

func (s *server) serve(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // allow large messages
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(response{JSONRPC: "2.0", ID: jsonNull, Error: &rpcError{codeParseError, "parse error"}})
			continue
		}
		s.handle(&req)
	}
	// The client is gone: stop any running scans before exiting.
	s.mu.Lock()
	for _, cancel := range s.inflight {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return sc.Err()
}

var jsonNull = json.RawMessage("null")

func (s *server) handle(req *request) {
	isNotification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		s.reply(req, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		})
	case "notifications/initialized":
		// notification: no reply
	case "notifications/cancelled":
		s.cancel(req.Params)
	case "ping":
		s.reply(req, map[string]any{})
	case "tools/list":
		s.reply(req, map[string]any{"tools": tools})
	case "tools/call":
		// Scans take minutes; run them off the read loop so pings and
		// cancellations are still handled.
		ctx, cancel := context.WithCancel(context.Background())
		key := string(req.ID)
		s.mu.Lock()
		if s.inflight == nil {
			s.inflight = map[string]context.CancelFunc{}
		}
		s.inflight[key] = cancel
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.inflight, key)
				s.mu.Unlock()
				cancel()
			}()
			s.handleToolCall(ctx, req)
		}()
	default:
		if isNotification {
			return // ignore unknown notifications
		}
		s.replyError(req, codeMethodMissing, "unknown method: "+req.Method)
	}
}

// cancel stops the in-flight request named by a notifications/cancelled.
func (s *server) cancel(params json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(params, &p) != nil || len(p.RequestID) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.inflight[string(p.RequestID)]; ok {
		cancel()
	}
}

// --- tools ---

var tools = []map[string]any{{
	"name":        "scan",
	"description": "Run attack-surface discovery against a domain: subdomain enumeration (passive sources via subfinder; with `subdomain_brute_force`, also a DNS brute-force of a wordlist, ignoring wildcard DNS), DNS resolution (dnsx), IP ownership/geo lookup (ipinfo.io), DNS and email security checks (SPF, DMARC, CAA, zone transfers, and subdomain takeovers: CNAMEs pointing at unclaimed third-party resources), HTTP probing of each host (httpx: status, title, technologies, CDN/WAF) and TLS certificate inspection (tlsx). A TCP port scan (naabu) of every resolved IP runs only when `ports` is true; resolved IPs can include third-party hosting and CDNs, so only enable it for infrastructure you are authorized to scan. With `services` (requires `ports`), each open port is actively probed to identify its service (product, version, CPEs); this needs nmap installed on the server, or `service_probes`. With `vulns`, the CVEs affecting each detected service's and web technology's version are looked up (NVD) with exploitation data from ProjectDiscovery's vulnx (KEV, EPSS, PoCs); the server reads optional API keys from NVD_API_KEY and PDCP_API_KEY. Port scanning is not available in Windows ARM64 builds. Use `skip` to turn stages off. Returns the full result as JSON.",
	"inputSchema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"domain":                map[string]any{"type": "string", "description": "Registrable domain to scan, e.g. example.com"},
			"skip":                  map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"ipdr", "misconfig", "web", "certs"}}, "description": "Stages to skip (subdomains and dns always run)"},
			"ports":                 map[string]any{"type": "boolean", "description": "Also run the TCP port scan (default false)"},
			"port_type":             map[string]any{"type": "string", "enum": []string{"connect", "syn"}, "description": "Port scan mode (default connect; syn needs root and libpcap)"},
			"port_spec":             map[string]any{"type": "string", "description": `Ports to scan: "-" for all (default), "1-1000", or "80,443"`},
			"port_rate":             map[string]any{"type": "integer", "description": "Packets/sec for the port scan"},
			"services":              map[string]any{"type": "boolean", "description": "Identify the service on each open port: product, version, CPEs (requires ports; default false)"},
			"service_probes":        map[string]any{"type": "string", "description": "Path to an nmap-service-probes file for services (defaults to a local nmap installation's copy)"},
			"vulns":                 map[string]any{"type": "boolean", "description": "Look up the CVEs affecting each detected service's and web technology's version, with KEV/EPSS/PoC data (needs services or the web stage; default false)"},
			"resolvers":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "DNS resolvers, e.g. udp:1.1.1.1:53"},
			"ipinfo_token":          map[string]any{"type": "string", "description": "ipinfo.io API token (optional)"},
			"subfinder_config":      map[string]any{"type": "string", "description": "Path to subfinder provider-config.yaml for API-key sources"},
			"subdomain_brute_force": map[string]any{"type": "boolean", "description": "After subfinder, also try each label of a wordlist as <label>.<domain>; one DNS query per label (default false)"},
			"subdomain_wordlist":    map[string]any{"type": "string", "description": "Path on the server to a file of subdomain labels, one per line, for subdomain_brute_force (default: built-in SecLists top 5,000)"},
		},
		"required": []string{"domain"},
	},
}}

type scanArgs struct {
	Domain              string   `json:"domain"`
	Skip                []string `json:"skip"`
	Ports               bool     `json:"ports"`
	PortType            string   `json:"port_type"`
	PortSpec            string   `json:"port_spec"`
	PortRate            int      `json:"port_rate"`
	Services            bool     `json:"services"`
	ServiceProbes       string   `json:"service_probes"`
	Vulns               bool     `json:"vulns"`
	Resolvers           []string `json:"resolvers"`
	IPInfoToken         string   `json:"ipinfo_token"`
	SubfinderConfig     string   `json:"subfinder_config"`
	SubdomainBruteforce bool     `json:"subdomain_brute_force"`
	SubdomainWordlist   string   `json:"subdomain_wordlist"`
}

func (s *server) handleToolCall(ctx context.Context, req *request) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &call); err != nil {
		s.replyError(req, codeInvalidParams, "invalid params")
		return
	}
	if call.Name != "scan" {
		s.replyError(req, codeInvalidParams, "unknown tool: "+call.Name)
		return
	}

	var a scanArgs
	if len(call.Arguments) > 0 {
		if err := json.Unmarshal(call.Arguments, &a); err != nil {
			s.replyError(req, codeInvalidParams, "invalid arguments: "+err.Error())
			return
		}
	}
	if a.Domain == "" {
		s.reply(req, toolError("domain is required"))
		return
	}
	if !a.Ports && (a.PortType != "" || a.PortSpec != "" || a.PortRate != 0 || a.Services) {
		s.reply(req, toolError("port_type, port_spec, port_rate and services require ports: true"))
		return
	}
	if !a.Services && a.ServiceProbes != "" {
		s.reply(req, toolError("service_probes requires services: true"))
		return
	}

	p := scan.Params{
		Domain:        a.Domain,
		Ports:         a.Ports,
		PortType:      a.PortType,
		PortSpec:      a.PortSpec,
		PortRate:      a.PortRate,
		Services:      a.Services,
		ServiceProbes: a.ServiceProbes,
		Vulns:         a.Vulns,
		// API keys come from the server's environment, never tool arguments.
		NVDAPIKey:           os.Getenv("NVD_API_KEY"),
		PDCPAPIKey:          os.Getenv("PDCP_API_KEY"),
		Resolvers:           a.Resolvers,
		IPInfoToken:         a.IPInfoToken,
		SubfinderCfg:        a.SubfinderConfig,
		SubdomainBruteforce: a.SubdomainBruteforce,
		SubdomainWordlist:   a.SubdomainWordlist,
	}
	if err := p.ApplySkips(a.Skip); err != nil {
		s.reply(req, toolError(err.Error()))
		return
	}
	if err := p.Validate(); err != nil {
		s.reply(req, toolError(err.Error()))
		return
	}

	res, err := scan.Run(ctx, p, nil, nil)
	if ctx.Err() != nil {
		return // cancelled: the spec says not to respond
	}
	if err != nil {
		s.reply(req, toolError("scan failed: "+err.Error()))
		return
	}

	payload, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		s.replyError(req, codeInternal, "encode result: "+err.Error())
		return
	}
	s.reply(req, map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(payload)}},
		"isError": false,
	})
}

// toolError is a tool-level failure (reported in the result, not as a
// protocol error) so the model sees it.
func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

// --- send helpers ---

func (s *server) reply(req *request, result any) {
	if len(req.ID) == 0 {
		return // notification: never reply
	}
	s.send(response{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (s *server) replyError(req *request, code int, msg string) {
	id := req.ID
	if len(id) == 0 {
		id = jsonNull
	}
	s.send(response{JSONRPC: "2.0", ID: id, Error: &rpcError{code, msg}})
}

func (s *server) send(resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		log.Println("marshal response:", err)
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.out.Write(b)
	s.out.WriteByte('\n')
	if err := s.out.Flush(); err != nil {
		log.Println("flush:", err)
	}
}
