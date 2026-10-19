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
