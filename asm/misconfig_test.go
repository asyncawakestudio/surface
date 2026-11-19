package asm

import (
	"fmt"
	"net"
	"strings"
	"testing"

	miekgdns "github.com/miekg/dns"
)

func TestCheckSPF(t *testing.T) {
	for _, tc := range []struct {
		txt          []string
		receivesMail bool
		want         string
	}{
		{[]string{"v=spf1 include:_spf.google.com -all"}, true, "[]"},
		{[]string{"v=spf1 include:_spf.google.com ~all"}, true, "[]"},
		{[]string{"v=spf1 redirect=_spf.example.com"}, true, "[]"},
		{[]string{"google-site-verification=x"}, true, "[medium:no SPF record]"},
		{nil, false, "[low:no SPF record;]"},
		{[]string{"v=spf1 -all", "v=spf1 mx -all"}, true, "[medium:2 SPF records:]"},
		{[]string{"v=spf1 +all"}, true, "[high:SPF allows any server]"},
		{[]string{"v=spf1 a mx all"}, true, "[high:SPF allows any server]"},
		{[]string{"v=spf1 mx ?all"}, true, "[medium:SPF ends in ?all]"},
		{[]string{"v=spf1 mx"}, true, `[medium:SPF has no "all"]`},
	} {
		if got := checkSPF(tc.txt, tc.receivesMail); !matchFindings(got, tc.want) {
			t.Errorf("checkSPF(%q) = %v, want %s", tc.txt, got, tc.want)
		}
	}
}

func TestCheckDMARC(t *testing.T) {
	for _, tc := range []struct {
		txt  []string
		want string
	}{
		{[]string{"v=DMARC1; p=reject; rua=mailto:d@example.com"}, "[]"},
		{[]string{"v=DMARC1; p=quarantine"}, "[]"},
		{nil, "[medium:no DMARC record:]"},
		{[]string{"v=DMARC1; p=none"}, "[medium:DMARC policy is p=none,]"},
		{[]string{"v=DMARC1; rua=mailto:d@example.com"}, "[medium:DMARC record has no]"},
		{[]string{"v=DMARC1; p=reject; sp=none; pct=50"}, "[low:DMARC subdomain policy low:DMARC applies to]"},
		{[]string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, "[medium:2 DMARC records:]"},
	} {
		if got := checkDMARC(tc.txt); !matchFindings(got, tc.want) {
			t.Errorf("checkDMARC(%q) = %v, want %s", tc.txt, got, tc.want)
		}
	}
}

// matchFindings reports whether fs matches want, written as
// "[severity:detail-prefix ...]" with one item per finding.
func matchFindings(fs []finding, want string) bool {
	items := splitWant(strings.TrimSuffix(strings.TrimPrefix(want, "["), "]"))
	if len(items) != len(fs) {
		return false
	}
	for i, f := range fs {
		sev, prefix, _ := strings.Cut(items[i], ":")
		if f.severity != sev || !strings.HasPrefix(f.detail, prefix) {
			return false
		}
	}
	return true
}

// splitWant splits "low:a b low:c" before each "severity:".
func splitWant(s string) []string {
	var out []string
	for _, w := range strings.Fields(s) {
		if strings.HasPrefix(w, "high:") || strings.HasPrefix(w, "medium:") || strings.HasPrefix(w, "low:") || len(out) == 0 {
			out = append(out, w)
			continue
		}
		out[len(out)-1] += " " + w
	}
	return out
}

// testZone serves example.com over UDP and TCP, including AXFR when
// allowAXFR is set, on the same 127.0.0.1 port.
func testZone(t *testing.T, records []string, allowAXFR bool) string {
	var rrs []miekgdns.RR
	for _, r := range records {
		rr, err := miekgdns.NewRR(r)
		if err != nil {
			t.Fatal(err)
		}
		rrs = append(rrs, rr)
	}
	soa, _ := miekgdns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600")
	handler := miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		q := r.Question[0]
		if q.Qtype == miekgdns.TypeAXFR {
			if !allowAXFR {
				m := new(miekgdns.Msg)
				m.SetRcode(r, miekgdns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			ch := make(chan *miekgdns.Envelope)
			tr := new(miekgdns.Transfer)
			go func() {
				ch <- &miekgdns.Envelope{RR: append(append([]miekgdns.RR{soa}, rrs...), soa)}
				close(ch)
			}()
			_ = tr.Out(w, r, ch)
			return
		}
		m := new(miekgdns.Msg)
		m.SetReply(r)
		for _, rr := range rrs {
			h := rr.Header()
			if strings.EqualFold(h.Name, q.Name) && h.Rrtype == q.Qtype {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []*miekgdns.Server{{Listener: l, Handler: handler}, {PacketConn: pc, Handler: handler}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return l.Addr().String()
}

func TestCheckMisconfigs(t *testing.T) {
	addr := testZone(t, []string{
		"example.com. 300 IN MX 10 mail.example.com.",
		`example.com. 300 IN TXT "v=spf1 include:_spf.example.net" " ?all"`,
		`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=none"`,
		"example.com. 300 IN NS 127.0.0.1.",
	}, true)
	_, port, _ := net.SplitHostPort(addr)
	defer func(p string) { axfrPort = p }(axfrPort)
	axfrPort = port

	s := New(Options{Resolvers: []string{"udp:" + addr}})
	// shop.example.com receives mail and has no SPF.
	records := []DNSRecord{{Host: "shop.example.com", Type: "MX", Value: "mx.example.net"}}
	got, err := s.checkMisconfigs(t.Context(), "example.com", records)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, m := range got {
		lines = append(lines, fmt.Sprintf("%s %s %s: %s", m.Host, m.Check, m.Severity, m.Detail))
	}
	want := []string{
		`example.com spf medium: SPF ends in ?all (neutral), which doesn't reject spoofed mail: "v=spf1 include:_spf.example.net ?all"`,
		"shop.example.com spf medium: no SPF record: anyone can send mail as this domain",
		`example.com dmarc medium: DMARC policy is p=none, which only monitors and doesn't stop spoofed mail: "v=DMARC1; p=none"`,
		"example.com caa low: no CAA record: any certificate authority may issue certificates for the domain",
		"example.com zone_transfer high: nameserver 127.0.0.1 allows zone transfers (AXFR): anyone can list all 6 records",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestZoneTransferRefused(t *testing.T) {
	addr := testZone(t, []string{"example.com. 300 IN NS 127.0.0.1."}, false)
	if n, ok := zoneTransfer(t.Context(), "example.com", addr); ok {
		t.Errorf("transfer succeeded with %d records", n)
	}
	if _, ok := zoneTransfer(t.Context(), "example.com", "127.0.0.1:1"); ok {
		t.Error("transfer from a closed port succeeded")
	}
}

func TestCompareMisconfigs(t *testing.T) {
	m := func(check string) Misconfiguration {
		return Misconfiguration{Host: "example.com", Check: check, Detail: check}
	}
	prev := &Result{Stages: []Stage{StageMisconfig}, Misconfigurations: []Misconfiguration{m("dmarc"), m("caa")}}
	cur := &Result{Stages: []Stage{StageMisconfig}, Misconfigurations: []Misconfiguration{m("caa"), m("spf")}}
	d := Compare(prev, cur).Misconfigs
	if !d.Compared || len(d.Added) != 1 || d.Added[0].Check != "spf" || len(d.Removed) != 1 || d.Removed[0].Check != "dmarc" {
		t.Errorf("diff = %+v", d)
	}
}
