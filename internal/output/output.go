// Package output renders an asm.Result in the formats the CLI supports:
// txt (one line per finding, in the style of ProjectDiscovery's tools), json
// (full fidelity), and csv/xml (flat, tabular).
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/asyncawakestudio/surface/asm"
	"github.com/asyncawakestudio/surface/internal/termui"
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

// Options tune rendering.
type Options struct {
	// Color colours the txt report with ANSI escapes, for a terminal.
	Color bool
}

// Render writes r to w in the given format, without colour.
func Render(w io.Writer, r *asm.Result, format string) error {
	return RenderWith(w, r, format, Options{})
}

// RenderWith writes r to w in the given format.
func RenderWith(w io.Writer, r *asm.Result, format string, opts Options) error {
	switch format {
	case "txt":
		return renderText(w, r, termui.Palette{On: opts.Color})
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
	for _, z := range r.ZoneTransfers {
		rows = append(rows, record{Type: "zone_transfer", Host: r.Domain, Field: z.Nameserver, Value: fmt.Sprintf("%d records", z.Records)})
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
	for _, a := range r.CloudAssets {
		ip := ""
		if len(a.IPs) > 0 {
			ip = a.IPs[0]
		}
		rows = append(rows, record{Type: "cloud", Host: a.Host, IP: ip, Field: cloudLabel(a), Value: cloudDetails(a)})
	}
	for _, idp := range r.Identity {
		rows = append(rows, record{Type: "identity", Host: idp.Domain, Field: idp.Provider, Value: identityDetails(idp)})
	}
	for _, b := range r.PublicBuckets {
		rows = append(rows, record{Type: "public_bucket", Host: bucketHost(b.URL), Field: b.Provider, Value: fmt.Sprintf("%s (%d objects listed)", b.URL, b.Objects)})
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

// renderText writes one line per finding, ProjectDiscovery style: the kind
// of finding in brackets, what it is about, then its details in brackets,
// e.g. "[web] https://example.com [200] [Home] [Nginx:1.18.0]". Empty details
// are left out, so every line can be grepped by its kind.
func renderText(w io.Writer, r *asm.Result, c termui.Palette) error {
	bw := &errWriter{w: w}
	line := func(kind, subject string, details ...string) {
		var b strings.Builder
		b.WriteString("[" + c.Blue(kind) + "] " + subject)
		for _, d := range details {
			if d != "" {
				b.WriteString(" [" + d + "]")
			}
		}
		b.WriteByte('\n')
		bw.write(b.String())
	}

	for _, s := range r.Subdomains {
		carried := ""
		if s.CarriedOver {
			carried = c.Gray("carried over")
		}
		line("subdomain", s.Host, c.Cyan(strings.Join(s.Sources, ",")), carried)
	}
	for _, d := range r.DNSRecords {
		line("dns", d.Host, c.Magenta(d.Type), c.Cyan(d.Value))
	}
	for _, z := range r.ZoneTransfers {
		line("zone-transfer", r.Domain, c.Cyan(z.Nameserver), c.Red(fmt.Sprintf("%d records", z.Records)))
	}
	for _, i := range r.IPInfo {
		if i.Error != "" {
			line("ipdr", i.IP, c.Red("error: "+i.Error))
			continue
		}
		var details []string
		for _, v := range ipInfoFields(i.Data) {
			details = append(details, c.Cyan(v))
		}
		line("ipdr", i.IP, details...)
	}
	for _, a := range r.CloudAssets {
		line("cloud", a.Host, c.Cyan(cloudLabel(a)), c.Cyan(a.Region), c.Gray(a.Evidence))
	}
	for _, idp := range r.Identity {
		var tenant, region, auth string
		if idp.TenantID != "" {
			tenant = c.Cyan("tenant " + idp.TenantID)
		}
		region = c.Cyan(idp.TenantRegion)
		switch {
		case idp.Authentication == "federated" && idp.AuthURL != "":
			auth = c.Yellow("federated " + idp.AuthURL)
		case idp.Authentication != "":
			auth = c.Cyan(idp.Authentication)
		}
		domains := ""
		if len(idp.Domains) > 0 {
			domains = c.Cyan(truncateList(idp.Domains, 10))
		}
		line("identity", idp.Domain, c.Green(idp.Provider), tenant, region, auth, c.Cyan(idp.URL), domains, c.Gray(idp.Evidence))
	}
	for _, b := range r.PublicBuckets {
		line("bucket", b.URL, c.Cyan(b.Provider), c.Red(fmt.Sprintf("%d objects listed", b.Objects)))
	}
	for _, ps := range r.PortScans {
		for _, pt := range ps.Ports {
			service := ""
			if pt.Service != nil {
				service = c.Cyan(serviceSummary(*pt.Service))
			}
			line("port", fmt.Sprintf("%s:%d", ps.IP, pt.Port), c.Gray(pt.Protocol), service)
		}
	}
	for _, wp := range r.Web {
		tech := techList(wp.Technologies)
		if tech == "" {
			tech = wp.WebServer
		}
		title := ""
		if wp.Title != "" {
			title = c.Yellow(wp.Title)
		}
		line("web", wp.URL, c.Status(wp.StatusCode), c.Gray(wp.Location), title, c.Cyan(tech), c.Magenta(wp.CDN))
	}
	for _, sv := range r.Vulnerabilities {
		for _, v := range sv.Vulnerabilities {
			line("vuln", fmt.Sprintf("%s:%d", sv.IP, sv.Port),
				c.Bold(v.ID), c.Severity(v.Severity), fmt.Sprintf("%.1f", v.CVSSScore),
				c.Cyan(serviceSummary(sv.Service)), c.Red(vulnFlagList(v)), vulnTitle(v))
		}
	}
	for _, crt := range r.TLSCerts {
		expires := ""
		if !crt.NotAfter.IsZero() {
			expires = "expires " + crt.NotAfter.Format("2006-01-02")
		}
		line("cert", fmt.Sprintf("%s:%d", crt.Host, crt.Port),
			c.Cyan(crt.SubjectCN), c.Gray("issuer: "+crt.IssuerCN), c.Gray(expires), c.Red(certFlagList(crt)))
	}
	return bw.err
}

// errWriter keeps the first write error, so the report can be written line
// by line and checked once.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) write(s string) {
	if e.err == nil {
		_, e.err = io.WriteString(e.w, s)
	}
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

// cloudLabel is "AWS EC2", or just "Heroku" when the service isn't known.
func cloudLabel(a asm.CloudAsset) string {
	return strings.TrimSpace(a.Provider + " " + a.Service)
}

// cloudDetails is the value of a csv/xml cloud row.
func cloudDetails(a asm.CloudAsset) string {
	parts := []string{"evidence=" + a.Evidence}
	if a.Region != "" {
		parts = append(parts, "region="+a.Region)
	}
	if len(a.IPs) > 0 {
		parts = append(parts, "ips="+strings.Join(a.IPs, "|"))
	}
	return strings.Join(parts, "; ")
}

// identityDetails is the value of a csv/xml identity row.
func identityDetails(idp asm.IdentityProvider) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("tenant", idp.TenantID)
	add("region", idp.TenantRegion)
	add("auth", idp.Authentication)
	add("auth_url", idp.AuthURL)
	add("brand", idp.BrandName)
	add("url", idp.URL)
	add("domains", strings.Join(idp.Domains, "|"))
	add("evidence", idp.Evidence)
	return strings.Join(parts, "; ")
}

// truncateList joins up to n items, noting how many more there are.
func truncateList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(items[:n], ", "), len(items)-n)
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

// techList lists technologies as "Name:Version,Name", as httpx does.
func techList(techs []asm.Technology) string {
	names := make([]string, len(techs))
	for i, t := range techs {
		names[i] = t.Name
		if t.Version != "" {
			names[i] += ":" + t.Version
		}
	}
	return strings.Join(names, ",")
}

// techNames lists technologies as "Name Version · Name".
func techNames(techs []asm.Technology) string {
	names := make([]string, len(techs))
	for i, t := range techs {
		names[i] = strings.TrimSpace(t.Name + " " + t.Version)
	}
	return strings.Join(names, " · ")
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

// vulnFlagList marks what makes a CVE urgent, e.g. "KEV, 19 PoCs, EPSS 0.80".
func vulnFlagList(v asm.Vulnerability) string {
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
	return strings.Join(f, ", ")
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

// flagSuffix is certFlagList as a suffix for csv/xml rows, e.g. "  [expired]".
func flagSuffix(c asm.TLSCert) string {
	if f := certFlagList(c); f != "" {
		return "  [" + f + "]"
	}
	return ""
}

// certFlagList lists what's wrong with a certificate, e.g. "expired, self-signed".
func certFlagList(c asm.TLSCert) string {
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
	return strings.Join(f, ", ")
}

// ipInfoFields picks the organisation and location from ipinfo data.
func ipInfoFields(data []byte) []string {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	var out []string
	for _, k := range []string{"org", "city", "region", "country"} {
		if v, ok := m[k].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// bucketHost is the host part of a bucket URL.
func bucketHost(u string) string {
	if _, rest, ok := strings.Cut(u, "://"); ok {
		u = rest
	}
	host, _, _ := strings.Cut(u, "/")
	return host
}
