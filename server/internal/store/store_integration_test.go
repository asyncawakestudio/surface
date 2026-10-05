//go:build integration

// Runs against a real, disposable database:
//
//	TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/store
package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"surface/internal/asm"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(ctx, `TRUNCATE scans RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	s := openTestStore(t)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("schema_migrations rows = %d, want 6", n)
	}
}

func TestScanHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScan(ctx, "example.com"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate active scan: err = %v, want ErrConflict", err)
	}
	must(t, s.MarkRunning(ctx, first.ID))
	must(t, s.SetStage(ctx, first.ID, "dns"))
	must(t, s.SaveResult(ctx, first.ID, &asm.Result{
		Subdomains: []asm.Subdomain{{Host: "a.example.com", Sources: []string{"crtsh"}}},
		DNSRecords: []asm.DNSRecord{{Host: "a.example.com", Type: "A", Value: "192.0.2.1"}},
		TLSCerts: []asm.TLSCert{{
			Host: "a.example.com", IP: "192.0.2.1", Port: 443, SANs: []string{"a.example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			FingerprintSHA256: "aaa",
		}},
	}))

	// A second scan of the same domain is allowed once the first finished.
	time.Sleep(10 * time.Millisecond) // distinct created_at
	paused, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.MarkPaused(ctx, paused.ID))

	time.Sleep(10 * time.Millisecond)
	latest, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatalf("scan after pause: %v", err)
	}
	must(t, s.SaveResult(ctx, latest.ID, &asm.Result{}))

	other, err := s.CreateScan(ctx, "other.example.org")
	if err != nil {
		t.Fatal(err)
	}

	// Previous completed skips the paused scan.
	prev, err := s.PreviousCompleted(ctx, latest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if prev.ID != first.ID || len(prev.Subdomains) != 1 || len(prev.TLSCerts) != 1 || prev.TLSCerts[0].SANs[0] != "a.example.com" {
		t.Fatalf("previous = %+v", prev)
	}
	if prev.Counts.Subdomains != 1 || prev.Counts.ResolvedHosts != 1 || prev.Counts.TLSCerts != 1 {
		t.Fatalf("counts = %+v", prev.Counts)
	}
	if _, err := s.PreviousCompleted(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("previous of first scan: err = %v, want ErrNotFound", err)
	}

	domains, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].Domain != "other.example.org" || domains[1].ScanCount != 3 ||
		domains[1].Latest.ID != latest.ID {
		t.Fatalf("domains = %+v", domains)
	}

	scans, err := s.ListScans(ctx, "example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 || scans[0].ID != latest.ID {
		t.Fatalf("scans = %+v", scans)
	}
	all, _ := s.ListScans(ctx, "", 10)
	if len(all) != 4 || all[0].ID != other.ID {
		t.Fatalf("all scans = %d, first = %d", len(all), all[0].ID)
	}

	n, err := s.FailInterrupted(ctx)
	if err != nil || n != 1 {
		t.Fatalf("FailInterrupted = %d, %v; want 1", n, err)
	}
}

func TestKnownSubdomains(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	scan := func(domain string, subs ...asm.Subdomain) {
		t.Helper()
		sc, err := s.CreateScan(ctx, domain)
		must(t, err)
		must(t, s.SaveResult(ctx, sc.ID, &asm.Result{Subdomains: subs}))
	}
	// Oldest scan has a host ("ancient") that later scans never carry forward.
	scan("example.com",
		asm.Subdomain{Host: "a.example.com", Sources: []string{"crtsh"}},
		asm.Subdomain{Host: "ancient.example.com", Sources: []string{"anubis"}})
	// Latest completed scan: this is the only set that should be carried forward.
	// a.example.com is carried over from scan #1 (no source found it again).
	scan("example.com",
		asm.Subdomain{Host: "a.example.com", Sources: []string{"crtsh", "virustotal"}, CarriedOver: true},
		asm.Subdomain{Host: "new.example.com", Sources: []string{"crtsh"}})
	scan("other.example.org", asm.Subdomain{Host: "x.other.example.org"})

	// A later paused scan's (absent) results don't count, and neither do other domains.
	paused, err := s.CreateScan(ctx, "example.com")
	must(t, err)
	must(t, s.MarkPaused(ctx, paused.ID))

	// Only the most recent completed scan (#2), not the union of all history:
	// "ancient.example.com" from scan #1 must NOT be carried forward.
	known, err := s.KnownSubdomains(ctx, "example.com")
	must(t, err)
	if len(known) != 2 ||
		known[0].Host != "a.example.com" || strings.Join(known[0].Sources, ",") != "crtsh,virustotal" ||
		known[1].Host != "new.example.com" || strings.Join(known[1].Sources, ",") != "crtsh" {
		t.Fatalf("known = %+v", known)
	}

	// carried_over round-trips: a.example.com true, new.example.com false
	// (subdomains are ordered by host).
	d, err := s.GetScan(ctx, 2)
	must(t, err)
	if !d.Subdomains[0].CarriedOver || d.Subdomains[1].CarriedOver {
		t.Fatalf("carried_over not round-tripped: %+v", d.Subdomains)
	}

	none, err := s.KnownSubdomains(ctx, "never-scanned.example.net")
	must(t, err)
	if none == nil || len(none) != 0 {
		t.Fatalf("known for unscanned domain = %#v, want empty slice", none)
	}
}

func TestIPInfoRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sc, err := s.CreateScan(ctx, "example.com")
	must(t, err)
	raw := `{"ip":"93.184.215.14","city":"Los Angeles","asn":{"asn":"AS15133","name":"Edgecast"}}`
	must(t, s.SaveResult(ctx, sc.ID, &asm.Result{IPInfo: []asm.IPInfo{
		{IP: "93.184.215.14", Data: json.RawMessage(raw)},
		{IP: "1.1.1.1", Error: "ipinfo: HTTP 429: Rate limit exceeded"},
	}}))

	d, err := s.GetScan(ctx, sc.ID)
	must(t, err)
	if d.Counts.IPAddresses != 2 || len(d.IPInfo) != 2 {
		t.Fatalf("count = %d, records = %+v", d.Counts.IPAddresses, d.IPInfo)
	}
	failed, ok := d.IPInfo[0], d.IPInfo[1] // ordered by ip
	if failed.IP != "1.1.1.1" || failed.Data != nil || !strings.Contains(failed.Error, "429") {
		t.Fatalf("failed record = %+v", failed)
	}
	var got, want map[string]any
	must(t, json.Unmarshal(ok.Data, &got))
	must(t, json.Unmarshal([]byte(raw), &want))
	if got["city"] != want["city"] || got["asn"].(map[string]any)["name"] != "Edgecast" || ok.Error != "" {
		t.Fatalf("ok record = %s / %q", ok.Data, ok.Error)
	}

	var nulls int
	must(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM ip_info WHERE data IS NULL`).Scan(&nulls))
	if nulls != 1 {
		t.Fatalf("SQL NULL data rows = %d, want 1 (not JSON null)", nulls)
	}
}

func TestPortScanRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sc, err := s.CreateScan(ctx, "example.com")
	must(t, err)
	must(t, s.SaveResult(ctx, sc.ID, &asm.Result{PortScans: []asm.PortScan{
		{IP: "93.184.215.14", Hosts: []string{"a.example.com", "b.example.com"}, Ports: []asm.OpenPort{
			{Port: 80, Protocol: "tcp"}, {Port: 443, Protocol: "tcp"},
		}},
		{IP: "10.0.0.1", Hosts: []string{"c.example.com"}, Ports: []asm.OpenPort{}}, // scanned, no open ports
	}}))

	d, err := s.GetScan(ctx, sc.ID)
	must(t, err)
	if d.Counts.OpenPorts != 2 {
		t.Fatalf("open port count = %d, want 2", d.Counts.OpenPorts)
	}
	if len(d.PortScans) != 2 {
		t.Fatalf("port scans = %d, want 2", len(d.PortScans))
	}
	first := d.PortScans[0] // ordered by ip: 10.0.0.1 < 93.184...
	if first.IP != "10.0.0.1" || len(first.Ports) != 0 || len(first.Hosts) != 1 {
		t.Fatalf("no-open-ports target not preserved: %+v", first)
	}
	second := d.PortScans[1]
	if second.IP != "93.184.215.14" || len(second.Ports) != 2 ||
		second.Ports[0].Port != 80 || second.Ports[1].Port != 443 {
		t.Fatalf("open ports = %+v", second.Ports)
	}
	if strings.Join(second.Hosts, ",") != "a.example.com,b.example.com" {
		t.Fatalf("hosts = %v", second.Hosts)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
