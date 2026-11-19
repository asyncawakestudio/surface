package output

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/asyncawakestudio/surface/asm"
)

func sample() *asm.Result {
	return &asm.Result{
		Domain:     "example.com",
		Subdomains: []asm.Subdomain{{Host: "www.example.com", Sources: []string{"crtsh", "vt"}}, {Host: "old.example.com", CarriedOver: true}},
		DNSRecords: []asm.DNSRecord{{Host: "www.example.com", Type: "A", Value: "1.2.3.4"}},
		IPInfo:     []asm.IPInfo{{IP: "1.2.3.4", Data: json.RawMessage(`{"org":"AS1 X","city":"LA"}`)}, {IP: "5.6.7.8", Error: "HTTP 429"}},
		PortScans:  []asm.PortScan{{IP: "1.2.3.4", Ports: []asm.OpenPort{{Port: 443, Protocol: "tcp"}}}},
		TLSCerts:   []asm.TLSCert{{Host: "www.example.com", Port: 443, SubjectCN: "example.com", IssuerCN: "R3"}},
	}
}

func TestValid(t *testing.T) {
	for _, f := range Formats {
		if !Valid(f) {
			t.Errorf("%s should be valid", f)
		}
	}
	if Valid("yaml") {
		t.Error("yaml should be invalid")
	}
}

func TestRenderAll(t *testing.T) {
	for _, f := range Formats {
		var b strings.Builder
		if err := Render(&b, sample(), f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !strings.Contains(b.String(), "www.example.com") {
			t.Errorf("%s output missing a known host:\n%s", f, b.String())
		}
	}
}

func TestRenderCSV(t *testing.T) {
	var b strings.Builder
	if err := Render(&b, sample(), "csv"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"type,host,ip,port,field,value",
		"subdomain,www.example.com,,,,crtsh|vt",
		"subdomain,old.example.com,,,carried_over,",
		"dns,www.example.com,,,A,1.2.3.4",
		"port,,1.2.3.4,443,tcp,open",
		"ipdr,,5.6.7.8,,error,HTTP 429",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("csv missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderXMLValid(t *testing.T) {
	var b strings.Builder
	if err := Render(&b, sample(), "xml"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Records []struct {
			Type string `xml:"type,attr"`
		} `xml:"record"`
	}
	if err := xml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("xml not well-formed: %v", err)
	}
	if len(doc.Records) != 7 {
		t.Errorf("records = %d, want 7", len(doc.Records))
	}
}

func TestRenderJSONFull(t *testing.T) {
	var b strings.Builder
	if err := Render(&b, sample(), "json"); err != nil {
		t.Fatal(err)
	}
	var r asm.Result
	if err := json.Unmarshal([]byte(b.String()), &r); err != nil {
		t.Fatalf("json invalid: %v", err)
	}
	if r.Domain != "example.com" || len(r.Subdomains) != 2 {
		t.Errorf("round-trip lost data: %+v", r)
	}
}

func withService() *asm.Result {
	r := sample()
	r.PortScans = []asm.PortScan{{IP: "1.2.3.4", Ports: []asm.OpenPort{
		{Port: 22, Protocol: "tcp", Service: &asm.Service{
			Name: "ssh", Product: "OpenSSH", Version: "8.9p1",
			CPEs: []string{"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"},
		}},
		{Port: 443, Protocol: "tcp", Service: &asm.Service{Name: "http", Product: "nginx", TLS: true}},
		{Port: 8080, Protocol: "tcp"},
	}}}
	return r
}

func TestRenderServices(t *testing.T) {
	cases := map[string][]string{
		"txt": {"22/tcp (ssh OpenSSH 8.9p1)", "443/tcp (http/tls nginx)", "8080/tcp"},
		"csv": {
			"port,,1.2.3.4,22,tcp,open",
			"service,,1.2.3.4,22,ssh,product=OpenSSH; version=8.9p1; cpe=cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
			"service,,1.2.3.4,443,http,product=nginx; tls",
		},
		"xml":  {`<record type="service" ip="1.2.3.4" port="22" field="ssh">product=OpenSSH; version=8.9p1;`},
		"json": {`"service": {`, `"product": "OpenSSH"`, `"cpes": [`},
	}
	for format, wants := range cases {
		var b strings.Builder
		if err := Render(&b, withService(), format); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		for _, want := range wants {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s output missing %q:\n%s", format, want, b.String())
			}
		}
	}

	// A port without a detected service has no service row.
	var b strings.Builder
	if err := Render(&b, withService(), "csv"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "service,,1.2.3.4,8080") {
		t.Error("csv has a service row for a port without a service")
	}
}

func TestRenderVulnerabilities(t *testing.T) {
	r := withService()
	r.Vulnerabilities = []asm.ServiceVulnerabilities{{
		ServiceTarget: asm.ServiceTarget{IP: "1.2.3.4", Port: 22, Protocol: "tcp", Service: *r.PortScans[0].Ports[0].Service},
		CPE:           "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
		Vulnerabilities: []asm.Vulnerability{
			{ID: "CVE-2023-38408", Severity: "critical", CVSSScore: 9.8, Enriched: true, Name: "OpenSSH - Command Injection", KEV: true, PoCs: 19, EPSSScore: 0.797},
			{ID: "CVE-2023-51385", Severity: "medium", CVSSScore: 6.5, Description: "In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters"},
		},
	}}
	cases := map[string][]string{
		"txt": {
			"Vulnerabilities\n  1.2.3.4:22  ssh OpenSSH 8.9p1 (2 CVEs)",
			"CVE-2023-38408   critical  9.8  OpenSSH - Command Injection  [KEV, 19 PoCs, EPSS 0.80]",
			"CVE-2023-51385   medium    6.5  In ssh in OpenSSH before 9.6, OS command injection might occur if a us...",
		},
		"csv": {
			"vuln,,1.2.3.4,22,CVE-2023-38408,severity=critical; cvss=9.8; kev; epss=0.7970; pocs=19; cpe=cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
			"vuln,,1.2.3.4,22,CVE-2023-51385,severity=medium; cvss=6.5; cpe=cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
		},
		"xml":  {`<record type="vuln" ip="1.2.3.4" port="22" field="CVE-2023-38408">severity=critical;`},
		"json": {`"vulnerabilities": [`, `"id": "CVE-2023-38408"`, `"kev": true`},
	}
	for format, wants := range cases {
		var b strings.Builder
		if err := Render(&b, r, format); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		for _, want := range wants {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s output missing %q:\n%s", format, want, b.String())
			}
		}
	}

	// Without a vulnerability lookup the section is absent.
	var b strings.Builder
	if err := Render(&b, withService(), "txt"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Vulnerabilities") {
		t.Error("txt has a Vulnerabilities section without a lookup")
	}
}

func TestRenderWeb(t *testing.T) {
	r := sample()
	r.Web = []asm.WebPage{
		{URL: "http://blog.example.com", Host: "blog.example.com", Port: 80, StatusCode: 301, Location: "https://blog.example.com/"},
		{URL: "https://www.example.com", Host: "www.example.com", IP: "1.2.3.4", Port: 443, StatusCode: 200, Title: "Home",
			Technologies: []asm.Technology{{Name: "Nginx", Version: "1.18.0"}, {Name: "WordPress", Version: "6.4.1"}}, CDN: "cloudflare"},
	}
	var b strings.Builder
	if err := Render(&b, r, "txt"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Web (2)\n",
		"  http://blog.example.com  301  → https://blog.example.com/\n",
		`  https://www.example.com  200  "Home"  Nginx 1.18.0 · WordPress 6.4.1  [cloudflare]` + "\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("txt missing %q in:\n%s", want, b.String())
		}
	}

	b.Reset()
	if err := Render(&b, r, "csv"); err != nil {
		t.Fatal(err)
	}
	want := "web,www.example.com,1.2.3.4,443,https://www.example.com,status=200; title=Home; tech=Nginx 1.18.0|WordPress 6.4.1; cdn=cloudflare"
	if !strings.Contains(b.String(), want) {
		t.Errorf("csv missing %q in:\n%s", want, b.String())
	}
}

func TestRenderMisconfigs(t *testing.T) {
	r := sample()
	r.Misconfigurations = []asm.Misconfiguration{
		{Host: "example.com", Check: "dmarc", Severity: "medium", Detail: "no DMARC record"},
		{Host: "example.com", Check: "zone_transfer", Severity: "high", Detail: "nameserver ns1.example.com allows zone transfers"},
		{Host: "assets.example.com", Check: "takeover", Severity: "high", CNAME: "assets-old.s3.amazonaws.com", Service: "AWS/S3",
			Detail: `CNAME assets-old.s3.amazonaws.com (AWS/S3) looks unclaimed: https response contains "NoSuchBucket"`},
		{Host: "www.example.com", Port: 8443, Check: "cert_expiring", Severity: "medium", Detail: "certificate for www.example.com expires on 2026-12-01"},
	}
	var b strings.Builder
	if err := Render(&b, r, "txt"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Misconfigurations (4)\n",
		"  medium  dmarc            example.com  no DMARC record\n",
		"  high    zone_transfer    example.com  nameserver ns1.example.com allows zone transfers\n",
		"  medium  cert_expiring    www.example.com:8443  certificate for www.example.com expires on 2026-12-01\n",
		`  high    takeover         assets.example.com  CNAME assets-old.s3.amazonaws.com (AWS/S3) looks unclaimed: https response contains "NoSuchBucket"` + "\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("txt missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	if err := Render(&b, r, "csv"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"misconfig,example.com,,,dmarc,medium: no DMARC record",
		"misconfig,www.example.com,,8443,cert_expiring,medium: certificate for www.example.com expires on 2026-12-01",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("csv missing %q in:\n%s", want, b.String())
		}
	}

	// A check that found nothing still says so.
	r.Misconfigurations, r.Stages = nil, []asm.Stage{asm.StageMisconfig}
	b.Reset()
	_ = Render(&b, r, "txt")
	if !strings.Contains(b.String(), "Misconfigurations (0)") {
		t.Errorf("txt:\n%s", b.String())
	}
}
