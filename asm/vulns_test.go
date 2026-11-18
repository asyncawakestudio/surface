package asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const opensshCPE = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"

func TestCPEHasVersion(t *testing.T) {
	for cpe, want := range map[string]bool{
		opensshCPE: true,
		"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*": false,
		"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*":     false,
		"cpe:2.3:a:vendor:product":                     false,
	} {
		if got := cpeHasVersion(cpe); got != want {
			t.Errorf("cpeHasVersion(%q) = %v, want %v", cpe, got, want)
		}
	}
}

func TestCPEVendorProduct(t *testing.T) {
	v, p, ok := cpeVendorProduct("cpe:2.3:a:OpenBSD:OpenSSH:*:*:*:*:*:*:*:*")
	if !ok || v != "openbsd" || p != "openssh" {
		t.Errorf("got %q, %q, %v", v, p, ok)
	}
	if _, _, ok := cpeVendorProduct("cpe:/a:openbsd:openssh"); ok {
		t.Error("CPE 2.2 should be rejected")
	}
}

func TestCompareVulns(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "CVE-2020-1", Severity: "medium", CVSSScore: 5},
		{ID: "CVE-2021-1", Severity: "critical", CVSSScore: 9.8},
		{ID: "CVE-2019-1", Severity: "low", CVSSScore: 3, KEV: true},
		{ID: "CVE-2022-1", Severity: "critical", CVSSScore: 9.1},
		{ID: "CVE-2023-1", Severity: "critical", CVSSScore: 9.8},
		{ID: "CVE-2024-1"}, // not scored yet
	}
	slices.SortFunc(vulns, compareVulns)
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	want := "CVE-2019-1,CVE-2023-1,CVE-2021-1,CVE-2022-1,CVE-2020-1,CVE-2024-1"
	if got := strings.Join(ids, ","); got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}

func TestNVDSeverity(t *testing.T) {
	var cve nvdCVE
	if err := json.Unmarshal([]byte(`{"metrics":{
		"cvssMetricV31":[
			{"type":"Secondary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}},
			{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}],
		"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":5.0},"baseSeverity":"MEDIUM"}]}}`), &cve); err != nil {
		t.Fatal(err)
	}
	if score, sev := cve.severity(); score != 9.8 || sev != "critical" {
		t.Errorf("v3.1 Primary: got %v %q", score, sev)
	}

	cve.Metrics.V31 = nil // falls back to v2, whose severity is outside cvssData
	if score, sev := cve.severity(); score != 5.0 || sev != "medium" {
		t.Errorf("v2: got %v %q", score, sev)
	}

	if score, sev := (nvdCVE{}).severity(); score != 0 || sev != "" {
		t.Errorf("unscored: got %v %q", score, sev)
	}
}

// nvdRecord is a CVE in NVD's API format with one cpeMatch.
func nvdRecord(id, criteria string, vulnerable bool) string {
	return fmt.Sprintf(`{"cve":{"id":%q,"published":"2024-07-01T13:15:10.457",
		"descriptions":[{"lang":"es","value":"es"},{"lang":"en","value":"desc %s"}],
		"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]},
		"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":%v,"criteria":%q}]}]}]}}`, id, id, vulnerable, criteria)
}

func TestNVDCVEsForCPE(t *testing.T) {
	const productCPE = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
	// Two pages, to check pagination; the second holds CVEs to filter out.
	pages := [][]string{
		{nvdRecord("CVE-2024-6387", productCPE, true)},
		{
			nvdRecord("CVE-2000-0001", "cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*", true), // other product
			nvdRecord("CVE-2000-0002", productCPE, false),                                     // only a platform
		},
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/rest/json/cves/2.0" || r.URL.Query().Get("virtualMatchString") != opensshCPE {
			t.Errorf("unexpected request %s", r.URL)
		}
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("apiKey header = %q", r.Header.Get("apiKey"))
		}
		page := pages[0]
		if r.URL.Query().Get("startIndex") != "0" {
			page = pages[1]
		}
		fmt.Fprintf(w, `{"totalResults":3,"vulnerabilities":[%s]}`, strings.Join(page, ","))
	}))
	defer srv.Close()

	c := newNVDClient(srv.URL, "k", srv.Client())
	c.interval = 0
	cves, err := c.cvesForCPE(t.Context(), opensshCPE)
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-6387" {
		t.Fatalf("cves = %+v, want only CVE-2024-6387", cves)
	}
	if requests.Load() != 2 {
		t.Errorf("requests = %d, want 2 (paginated)", requests.Load())
	}
	if d := cves[0].description(); d != "desc CVE-2024-6387" {
		t.Errorf("description = %q, want the English one", d)
	}
	if p := cves[0].published(); !p.Equal(time.Date(2024, 7, 1, 13, 15, 10, 457e6, time.UTC)) {
		t.Errorf("published = %v", p)
	}
}

func TestNVDRetriesWhenThrottled(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden) // NVD's rate-limit response
			return
		}
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	c := newNVDClient(srv.URL, "", srv.Client())
	c.interval = time.Millisecond
	if _, err := c.cvesForCPE(t.Context(), opensshCPE); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Errorf("requests = %d, want 2 (one retry)", requests.Load())
	}
}

func TestNVDDoesNotRetryClientErrors(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "bad cpe", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newNVDClient(srv.URL, "", srv.Client())
	c.interval = 0
	_, err := c.cvesForCPE(t.Context(), opensshCPE)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || requests.Load() != 1 {
		t.Errorf("err = %v after %d requests, want one HTTP 404", err, requests.Load())
	}
}

func TestLookupVulns(t *testing.T) {
	const productCPE = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
	var nvdRequests atomic.Int32
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nvdRequests.Add(1)
		fmt.Fprintf(w, `{"totalResults":3,"vulnerabilities":[%s,%s,%s]}`,
			nvdRecord("CVE-2023-38408", productCPE, true),
			nvdRecord("CVE-2024-6387", productCPE, true),
			nvdRecord("CVE-2023-51385", productCPE, true))
	}))
	defer nvd.Close()
	vulnx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-PDCP-Key"); got != "pd" {
			t.Errorf("X-PDCP-Key = %q", got)
		}
		switch strings.TrimPrefix(r.URL.Path, "/v2/vulnerability/") {
		case "CVE-2023-38408":
			fmt.Fprint(w, `{"data":{"cve_id":"CVE-2023-38408","name":"OpenSSH - Command Injection","is_kev":true,"epss_score":0.797,"epss_percentile":0.996,"poc_count":19,"is_remote":true,"is_patch_available":true}}`)
		case "CVE-2024-6387":
			fmt.Fprint(w, `{"data":{"cve_id":"CVE-2024-6387","name":"regreSSHion","is_template":true,"poc_count":40}}`)
		case "CVE-2023-51385":
			http.Error(w, "boom", http.StatusInternalServerError) // enrichment failure: still reported
		}
	}))
	defer vulnx.Close()

	s := New(Options{
		NVDBaseURL: nvd.URL, VulnxBaseURL: vulnx.URL, PDCPAPIKey: "pd",
		HTTPClient: nvd.Client(),
	})
	ssh := Service{Name: "ssh", Product: "OpenSSH", Version: "8.9p1", CPEs: []string{
		opensshCPE, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
	}}
	services := []ServiceTarget{
		{IP: "192.0.2.1", Hosts: []string{"a.example.com"}, Port: 22, Protocol: "tcp", Service: ssh},
		{IP: "192.0.2.2", Hosts: []string{"b.example.com"}, Port: 2222, Protocol: "tcp", Service: ssh},
		{IP: "192.0.2.3", Port: 80, Protocol: "tcp", Service: Service{Name: "http"}}, // no CPE
	}

	got, err := s.lookupVulns(t.Context(), services)
	if err != nil {
		t.Fatal(err)
	}
	if nvdRequests.Load() != 1 {
		t.Errorf("NVD requests = %d, want 1 (same CPE on two services, version-less CPE skipped)", nvdRequests.Load())
	}
	if len(got) != 2 || got[0].IP != "192.0.2.1" || got[1].Port != 2222 || got[0].CPE != opensshCPE {
		t.Fatalf("got %+v, want both SSH services", got)
	}

	vulns := got[0].Vulnerabilities
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	// KEV first; the rest by severity (equal here) then newest ID first.
	if want := "CVE-2023-38408,CVE-2024-6387,CVE-2023-51385"; strings.Join(ids, ",") != want {
		t.Errorf("order = %s, want %s", strings.Join(ids, ","), want)
	}
	kev := vulns[0]
	if !kev.Enriched || !kev.KEV || kev.PoCs != 19 || kev.EPSSScore != 0.797 || !kev.Remote ||
		!kev.PatchAvailable || kev.Name != "OpenSSH - Command Injection" || kev.Severity != "high" || kev.CVSSScore != 8.1 {
		t.Errorf("CVE-2023-38408 = %+v", kev)
	}
	if !vulns[1].NucleiTemplate || vulns[1].PoCs != 40 {
		t.Errorf("CVE-2024-6387 = %+v", vulns[1])
	}
	if vulns[2].Enriched || vulns[2].Severity != "high" {
		t.Errorf("CVE-2023-51385 = %+v, want NVD data without enrichment", vulns[2])
	}

	// Each service gets its own copy of the CVE list.
	got[0].Vulnerabilities[0].Name = "changed"
	if got[1].Vulnerabilities[0].Name == "changed" {
		t.Error("services share their vulnerability slices")
	}
}

func TestLookupVulnsNoVersionedCPEs(t *testing.T) {
	s := New(Options{NVDBaseURL: "http://127.0.0.1:1", VulnxBaseURL: "http://127.0.0.1:1"})
	got, err := s.lookupVulns(t.Context(), []ServiceTarget{{Service: Service{Name: "ssh",
		CPEs: []string{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}}}})
	if err != nil || got != nil {
		t.Errorf("got %+v, %v; want nil, nil without contacting NVD", got, err)
	}
}

func TestRunVulnLookupNeedsServiceDetection(t *testing.T) {
	_, err := New(Options{PortScan: true, VulnLookup: true, SkipWeb: true}).Run(t.Context(), Target{Domain: "example.com"}, nil)
	if !errors.Is(err, ErrVulnLookupNeedsServices) {
		t.Fatalf("err = %v, want ErrVulnLookupNeedsServices", err)
	}
}
