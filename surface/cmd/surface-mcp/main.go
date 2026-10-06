// Command surface-mcp exposes the core discovery service to AI clients over
// the Model Context Protocol (MCP) on stdio. It speaks newline-delimited
// JSON-RPC 2.0 — the MCP stdio transport — with no external dependencies.
//
// Tool: scan(domain, ...) runs the full discovery pipeline and returns the
// result as JSON text. Configure an MCP client to launch this binary over
// stdio.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"

	"surface/internal/scan"
)

const (
	protocolVersion = "2024-11-05"
	serverName      = "surface"
	serverVersion   = "dev"
)

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
	out         *bufio.Writer
	initialized bool
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
		s.initialized = true // notification: no reply
	case "ping":
		s.reply(req, map[string]any{})
	case "tools/list":
		s.reply(req, map[string]any{"tools": tools})
	case "tools/call":
		s.handleToolCall(req)
	default:
		if isNotification {
			return // ignore unknown notifications
		}
		s.replyError(req, codeMethodMissing, "unknown method: "+req.Method)
	}
}

// --- tools ---

var tools = []map[string]any{{
	"name":        "scan",
	"description": "Run attack-surface discovery against a domain. By default every stage runs: passive subdomain enumeration (subfinder), DNS resolution (dnsx), IP ownership/geo lookup (ipinfo.io), a TCP port scan of all ports (naabu), and TLS certificate inspection (tlsx). Use `skip` to turn stages off. Returns the full result as JSON.",
	"inputSchema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"domain":           map[string]any{"type": "string", "description": "Registrable domain to scan, e.g. example.com"},
			"skip":             map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"ipdr", "ports", "certs"}}, "description": "Stages to skip (subdomains and dns always run)"},
			"port_type":        map[string]any{"type": "string", "enum": []string{"syn", "connect"}, "description": "Port scan mode (default connect)"},
			"port_spec":        map[string]any{"type": "string", "description": `Ports to scan: "-" for all (default), "1-1000", or "80,443"`},
			"port_rate":        map[string]any{"type": "integer", "description": "Packets/sec for the port scan"},
			"resolvers":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "DNS resolvers, e.g. udp:1.1.1.1:53"},
			"ipinfo_token":     map[string]any{"type": "string", "description": "ipinfo.io API token (optional)"},
			"subfinder_config": map[string]any{"type": "string", "description": "Path to subfinder provider-config.yaml for API-key sources"},
		},
		"required": []string{"domain"},
	},
}}

type scanArgs struct {
	Domain          string   `json:"domain"`
	Skip            []string `json:"skip"`
	PortType        string   `json:"port_type"`
	PortSpec        string   `json:"port_spec"`
	PortRate        int      `json:"port_rate"`
	Resolvers       []string `json:"resolvers"`
	IPInfoToken     string   `json:"ipinfo_token"`
	SubfinderConfig string   `json:"subfinder_config"`
}

func (s *server) handleToolCall(req *request) {
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

	p := scan.Params{
		Domain:       a.Domain,
		PortType:     a.PortType,
		PortSpec:     a.PortSpec,
		PortRate:     a.PortRate,
		Resolvers:    a.Resolvers,
		IPInfoToken:  a.IPInfoToken,
		SubfinderCfg: a.SubfinderConfig,
	}
	if err := p.ApplySkips(a.Skip); err != nil {
		s.reply(req, toolError(err.Error()))
		return
	}

	res, err := scan.Run(context.Background(), p, nil, nil)
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
	s.out.Write(b)
	s.out.WriteByte('\n')
	if err := s.out.Flush(); err != nil {
		log.Println("flush:", err)
	}
}
