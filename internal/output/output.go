// Package output renders an asm.Result in the formats the CLI supports:
// txt (human report), json (full fidelity), and csv/xml (flat, tabular).
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/asyncawakestudio/surface/asm"
)

// Formats lists the valid output formats (the CLI's --output values).
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
			if p.Service != nil {
				rows = append(rows, record{Type: "service", IP: ps.IP, Port: p.Port, Field: p.Service.Name, Value: serviceDetails(*p.Service)})
			}
		}
	}
	for _, m := range r.Misconfigurations {
		rows = append(rows, record{Type: "misconfig", Host: m.Host, Port: m.Port, Field: m.Check, Value: m.Severity + ": " + m.Detail})
	}
	for _, wp := range r.Web {
		rows = append(rows, record{Type: "web", Host: wp.Host, IP: wp.IP, Port: wp.Port, Field: wp.URL, Value: webDetails(wp)})
	}
	for _, sv := range r.Vulnerabilities {
		for _, v := range sv.Vulnerabilities {
			rows = append(rows, record{Type: "vuln", IP: sv.IP, Port: sv.Port, Field: v.ID, Value: vulnDetails(v, sv.CPE)})
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

	if len(r.Misconfigurations) > 0 || slices.Contains(r.Stages, asm.StageMisconfig) {
		p("\nMisconfigurations (%d)\n", len(r.Misconfigurations))
		for _, m := range r.Misconfigurations {
			host := m.Host
			if m.Port != 0 {
				host += ":" + strconv.Itoa(m.Port)
			}
			p("  %-6s  %-16s %s  %s\n", m.Severity, m.Check, host, m.Detail)
		}
	}

	if len(r.PortScans) > 0 {
		p("\nOpen ports\n")
		for _, ps := range r.PortScans {
			ports := make([]string, len(ps.Ports))
			for j, pt := range ps.Ports {
				ports[j] = fmt.Sprintf("%d/%s", pt.Port, pt.Protocol)
				if pt.Service != nil {
					ports[j] += " (" + serviceSummary(*pt.Service) + ")"
				}
			}
			p("  %-18s %s\n", ps.IP, strings.Join(ports, ", "))
		}
	}

	if len(r.Web) > 0 {
		width := 0
		for _, wp := range r.Web {
			width = max(width, len(wp.URL))
		}
		p("\nWeb (%d)\n", len(r.Web))
		for _, wp := range r.Web {
			p("  %-*s  %s\n", width, wp.URL, webSummary(wp))
		}
	}

	if len(r.Vulnerabilities) > 0 {
		p("\nVulnerabilities\n")
		for _, sv := range r.Vulnerabilities {
			p("  %s:%d%s  %s (%d CVEs)\n", sv.IP, sv.Port, hostsSuffix(sv.Hosts), serviceSummary(sv.Service), len(sv.Vulnerabilities))
			for _, v := range sv.Vulnerabilities {
				p("    %-16s %-8s %4.1f  %s%s\n", v.ID, v.Severity, v.CVSSScore, vulnTitle(v), vulnFlags(v))
			}
		}
	}

	p("\nTLS certificates (%d)\n", len(r.TLSCerts))
	for _, c := range r.TLSCerts {
		p("  %s:%d  %s  (issuer: %s)%s\n", c.Host, c.Port, c.SubjectCN, c.IssuerCN, flagSuffix(c))
	}
	p("\n")
	return nil
}

// serviceSummary is a short label for the txt report, e.g. "ssh OpenSSH 8.9p1".
func serviceSummary(s asm.Service) string {
	parts := []string{s.Name}
	if s.TLS {
		parts[0] += "/tls"
	}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	return strings.Join(parts, " ")
}

// serviceDetails is the value of a csv/xml service row, e.g.
// "product=OpenSSH; version=8.9p1; cpe=cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*".
func serviceDetails(s asm.Service) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("product", s.Product)
	add("version", s.Version)
	add("info", s.ExtraInfo)
	if s.TLS {
		parts = append(parts, "tls")
	}
	add("cpe", strings.Join(s.CPEs, "|"))
	return strings.Join(parts, "; ")
}

// webSummary is a page's line in the txt report, e.g.
// `200  "Home"  Nginx 1.18.0 · WordPress 6.4.1  [cloudflare]`.
func webSummary(wp asm.WebPage) string {
	parts := []string{strconv.Itoa(wp.StatusCode)}
	if wp.Location != "" {
		parts = append(parts, "→ "+wp.Location)
	}
	if wp.Title != "" {
		parts = append(parts, strconv.Quote(wp.Title))
	}
	if techs := techNames(wp.Technologies); techs != "" {
		parts = append(parts, techs)
	} else if wp.WebServer != "" {
		parts = append(parts, wp.WebServer)
	}
	if wp.CDN != "" {
		parts = append(parts, "["+wp.CDN+"]")
	}
	return strings.Join(parts, "  ")
}

// webDetails is the value of a csv/xml web row.
func webDetails(wp asm.WebPage) string {
	parts := []string{fmt.Sprintf("status=%d", wp.StatusCode)}
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("location", wp.Location)
	add("title", wp.Title)
	add("server", wp.WebServer)
	add("tech", strings.ReplaceAll(techNames(wp.Technologies), " · ", "|"))
	add("cdn", wp.CDN)
	return strings.Join(parts, "; ")
}

// techNames lists technologies as "Name Version · Name".
func techNames(techs []asm.Technology) string {
	names := make([]string, len(techs))
	for i, t := range techs {
		names[i] = strings.TrimSpace(t.Name + " " + t.Version)
	}
	return strings.Join(names, " · ")
}

// hostsSuffix names up to three hosts, e.g. " (a.example.com, b.example.com +2)".
func hostsSuffix(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	const maxHosts = 3
	if len(hosts) <= maxHosts {
		return " (" + strings.Join(hosts, ", ") + ")"
	}
	return fmt.Sprintf(" (%s +%d)", strings.Join(hosts[:maxHosts], ", "), len(hosts)-maxHosts)
}

// vulnTitle is vulnx's short name, or the start of NVD's description.
func vulnTitle(v asm.Vulnerability) string {
	if v.Name != "" {
		return v.Name
	}
	const maxLen = 70
	d := strings.Join(strings.Fields(v.Description), " ")
	if len(d) > maxLen {
		return d[:maxLen] + "..."
	}
	return d
}

// vulnFlags marks what makes a CVE urgent, e.g. "  [KEV, 19 PoCs, EPSS 0.80]".
func vulnFlags(v asm.Vulnerability) string {
	var f []string
	if v.KEV {
		f = append(f, "KEV")
	}
	if v.PoCs > 0 {
		f = append(f, fmt.Sprintf("%d PoCs", v.PoCs))
	}
	if v.NucleiTemplate {
		f = append(f, "nuclei")
	}
	if v.EPSSScore > 0 {
		f = append(f, fmt.Sprintf("EPSS %.2f", v.EPSSScore))
	}
	if len(f) == 0 {
		return ""
	}
	return "  [" + strings.Join(f, ", ") + "]"
}

// vulnDetails is the value of a csv/xml vuln row.
func vulnDetails(v asm.Vulnerability, cpe string) string {
	parts := []string{"severity=" + v.Severity, fmt.Sprintf("cvss=%.1f", v.CVSSScore)}
	if v.KEV {
		parts = append(parts, "kev")
	}
	if v.Enriched {
		parts = append(parts, fmt.Sprintf("epss=%.4f", v.EPSSScore), fmt.Sprintf("pocs=%d", v.PoCs))
	}
	if v.NucleiTemplate {
		parts = append(parts, "nuclei")
	}
	parts = append(parts, "cpe="+cpe)
	return strings.Join(parts, "; ")
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
