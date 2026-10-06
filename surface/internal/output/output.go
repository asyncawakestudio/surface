// Package output renders an asm.Result in the formats the CLI supports:
// txt (human report), json (full fidelity), and csv/xml (flat, tabular).
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"surface/asm"
)

// Formats lists the valid --out-format values.
var Formats = []string{"txt", "json", "csv", "xml"}

// Valid reports whether format is a supported output format.
func Valid(format string) bool {
	for _, f := range Formats {
		if f == format {
			return true
		}
	}
	return false
}

// Render writes r to w in the given format.
func Render(w io.Writer, r *asm.Result, format string) error {
	switch format {
	case "txt":
		return renderText(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		return renderCSV(w, r)
	case "xml":
		return renderXML(w, r)
	default:
		return fmt.Errorf("unknown format %q (valid: %s)", format, strings.Join(Formats, ", "))
	}
}

// --- flat tabular model (shared by csv and xml) ---

type record struct {
	Type  string `xml:"type,attr"`
	Host  string `xml:"host,attr,omitempty"`
	IP    string `xml:"ip,attr,omitempty"`
	Port  int    `xml:"port,attr,omitempty"`
	Field string `xml:"field,attr,omitempty"`
	Value string `xml:",chardata"`
}

func flatten(r *asm.Result) []record {
	var rows []record
	for _, s := range r.Subdomains {
		field := ""
		if s.CarriedOver {
			field = "carried_over"
		}
		rows = append(rows, record{Type: "subdomain", Host: s.Host, Field: field, Value: strings.Join(s.Sources, "|")})
	}
	for _, d := range r.DNSRecords {
		rows = append(rows, record{Type: "dns", Host: d.Host, Field: d.Type, Value: d.Value})
	}
	for _, i := range r.IPInfo {
		rec := record{Type: "ipdr", IP: i.IP, Field: "data", Value: string(i.Data)}
		if i.Error != "" {
			rec.Field, rec.Value = "error", i.Error
		}
		rows = append(rows, rec)
	}
	for _, ps := range r.PortScans {
		for _, p := range ps.Ports {
			rows = append(rows, record{Type: "port", IP: ps.IP, Port: p.Port, Field: p.Protocol, Value: "open"})
		}
	}
	for _, c := range r.TLSCerts {
		rows = append(rows, record{
			Type: "certs", Host: c.Host, Port: c.Port, Field: "cert",
			Value: fmt.Sprintf("subject=%s; issuer=%s; expires=%s%s",
				c.SubjectCN, c.IssuerCN, c.NotAfter.Format("2006-01-02"), flagSuffix(c)),
		})
	}
	return rows
}

func renderCSV(w io.Writer, r *asm.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"type", "host", "ip", "port", "field", "value"}); err != nil {
		return err
	}
	for _, rec := range flatten(r) {
		port := ""
		if rec.Port != 0 {
			port = strconv.Itoa(rec.Port)
		}
		if err := cw.Write([]string{rec.Type, rec.Host, rec.IP, port, rec.Field, rec.Value}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func renderXML(w io.Writer, r *asm.Result) error {
	doc := struct {
		XMLName xml.Name `xml:"surface"`
		Domain  string   `xml:"domain,attr"`
		Records []record `xml:"record"`
	}{Domain: r.Domain, Records: flatten(r)}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// --- human report ---

func renderText(w io.Writer, r *asm.Result) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("\nSurface report for %s\n%s\n", r.Domain, strings.Repeat("=", 40))

	p("\nSubdomains (%d)\n", len(r.Subdomains))
	for _, s := range r.Subdomains {
		tag := ""
		if s.CarriedOver {
			tag = "  [carried over]"
		}
		p("  %s%s\n", s.Host, tag)
	}

	p("\nDNS records (%d)\n", len(r.DNSRecords))
	for _, d := range r.DNSRecords {
		p("  %-40s %-6s %s\n", d.Host, d.Type, d.Value)
	}

	p("\nIPDR (%d)\n", len(r.IPInfo))
	for _, i := range r.IPInfo {
		if i.Error != "" {
			p("  %-18s error: %s\n", i.IP, i.Error)
			continue
		}
		p("  %-18s %s\n", i.IP, summarizeIPInfo(i.Data))
	}

	if len(r.PortScans) > 0 {
		p("\nOpen ports\n")
		for _, ps := range r.PortScans {
			ports := make([]string, len(ps.Ports))
			for j, pt := range ps.Ports {
				ports[j] = fmt.Sprintf("%d/%s", pt.Port, pt.Protocol)
			}
			p("  %-18s %s\n", ps.IP, strings.Join(ports, ", "))
		}
	}

	p("\nTLS certificates (%d)\n", len(r.TLSCerts))
	for _, c := range r.TLSCerts {
		p("  %s:%d  %s  (issuer: %s)%s\n", c.Host, c.Port, c.SubjectCN, c.IssuerCN, flagSuffix(c))
	}
	p("\n")
	return nil
}

func flagSuffix(c asm.TLSCert) string {
	var f []string
	if c.Expired {
		f = append(f, "expired")
	}
	if c.SelfSigned {
		f = append(f, "self-signed")
	}
	if c.Mismatched {
		f = append(f, "mismatched")
	}
	if len(f) == 0 {
		return ""
	}
	return "  [" + strings.Join(f, ", ") + "]"
}

func summarizeIPInfo(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	var parts []string
	for _, k := range []string{"org", "city", "region", "country"} {
		if v, ok := m[k].(string); ok && v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " · ")
}
