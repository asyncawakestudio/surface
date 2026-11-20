package asm

import (
	"fmt"
	"net"
	"strings"
	"testing"

	miekgdns "github.com/miekg/dns"
)

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
		if !strings.HasSuffix(strings.ToLower(q.Name), "example.com.") {
			m.SetRcode(r, miekgdns.RcodeNameError) // outside the zone: doesn't exist
		}
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

func TestLookupDomainRecords(t *testing.T) {
	addr := testZone(t, []string{
		"example.com. 300 IN MX 10 mail.example.com.",
		`example.com. 300 IN TXT "v=spf1 include:_spf.example.com" " -all"`,
		`_spf.example.com. 300 IN TXT "v=spf1 include:_spf2.example.com redirect=_spf.example.com ~all"`,
		`_spf2.example.com. 300 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"`,
		`_spf2.example.com. 300 IN TXT "not spf, kept anyway"`,
		`_dmarc.example.com. 300 IN TXT "v=DMARC1; " "p=none"`,
		`_mta-sts.example.com. 300 IN TXT "v=STSv1; id=20260101"`,
		`_smtp._tls.example.com. 300 IN TXT "v=TLSRPTv1; rua=mailto:tls@example.com"`,
		`selector1._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p=MIGf"`,
		`_dmarc.shop.example.com. 300 IN TXT "v=DMARC1; p=reject"`,
		"_25._tcp.mail.example.com. 300 IN TLSA 3 1 1 0123456789abcdef",
		"example.com. 300 IN NS 127.0.0.1.",
	}, true)
	_, port, _ := net.SplitHostPort(addr)
	defer func(p string) { axfrPort = p }(axfrPort)
	axfrPort = port

	// The host queries found shop.example.com's MX and nothing for the root.
	known := []DNSRecord{{Host: "shop.example.com", Type: "MX", Value: "mx.example.net"}}
	records, transfers, err := New(Options{Resolvers: []string{"udp:" + addr}}).lookupDomainRecords(t.Context(), "example.com", known)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range records {
		got = append(got, r.Host+" "+r.Type+" "+r.Value)
	}
	want := []string{
		"example.com MX mail.example.com",
		"example.com TXT v=spf1 include:_spf.example.com -all",
		"_dmarc.example.com TXT v=DMARC1; p=none",
		"_mta-sts.example.com TXT v=STSv1; id=20260101",
		"_smtp._tls.example.com TXT v=TLSRPTv1; rua=mailto:tls@example.com",
		"selector1._domainkey.example.com TXT v=DKIM1; k=rsa; p=MIGf",
		"_dmarc.shop.example.com TXT v=DMARC1; p=reject",
		// DANE for the root's mail server; mx.example.net has none.
		"_25._tcp.mail.example.com TLSA 3 1 1 0123456789abcdef",
		// SPF includes, followed once each.
		"_spf.example.com TXT v=spf1 include:_spf2.example.com redirect=_spf.example.com ~all",
		"_spf2.example.com TXT v=spf1 ip4:192.0.2.0/24 -all",
		"_spf2.example.com TXT not spf, kept anyway",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The SOA is sent at the start and the end of the transfer.
	if want := "[{127.0.0.1 14}]"; fmt.Sprint(transfers) != want {
		t.Errorf("transfers = %v, want %s", transfers, want)
	}
}

func TestLookupDomainRecordsNoMail(t *testing.T) {
	// No MX anywhere: none of the email records are looked up, even though
	// the zone has them.
	addr := testZone(t, []string{
		`example.com. 300 IN TXT "v=spf1 -all"`,
		`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`,
		"example.com. 300 IN NS 127.0.0.1.",
	}, false)
	records, _, err := New(Options{Resolvers: []string{"udp:" + addr}}).lookupDomainRecords(t.Context(), "example.com", nil)
	if err != nil || records != nil {
		t.Errorf("got %v, %v; want no records", records, err)
	}
}

func TestLookupDomainRecordsNothingFound(t *testing.T) {
	addr := testZone(t, []string{"example.com. 300 IN NS 127.0.0.1."}, false)
	_, port, _ := net.SplitHostPort(addr)
	defer func(p string) { axfrPort = p }(axfrPort)
	axfrPort = port

	records, transfers, err := New(Options{Resolvers: []string{"udp:" + addr}}).lookupDomainRecords(t.Context(), "example.com", nil)
	if err != nil || records != nil || transfers != nil {
		t.Errorf("got %v, %v, %v; want nothing", records, transfers, err)
	}
}

func TestSPFTargets(t *testing.T) {
	records := []DNSRecord{
		{Host: "example.com", Type: "TXT", Value: "v=spf1 include:_spf.google.com ~include:spf.Protection.Outlook.com. exists:%{i}.x.example.com redirect=_spf.example.com -all"},
		{Host: "example.com", Type: "TXT", Value: "google-site-verification=abc include:not.spf"},
		{Host: "other.example.com", Type: "TXT", Value: "v=spf1 include:ignored.example -all"},
	}
	got := spfTargets(records, []string{"example.com"})
	if want := "[_spf.google.com spf.protection.outlook.com _spf.example.com]"; fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
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

func TestCompareZoneTransfers(t *testing.T) {
	prev := &Result{ZoneTransfers: []ZoneTransfer{{Nameserver: "ns1.example.com", Records: 10}}}
	cur := &Result{ZoneTransfers: []ZoneTransfer{{Nameserver: "ns2.example.com", Records: 12}}}
	d := Compare(prev, cur).ZoneTransfers
	if fmt.Sprint(d.Added) != "[{ns2.example.com 12}]" || fmt.Sprint(d.Removed) != "[{ns1.example.com 10}]" {
		t.Errorf("diff = %+v", d)
	}
}
