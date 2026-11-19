package asm

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	miekgdns "github.com/miekg/dns"
)

func TestTakeoverFingerprints(t *testing.T) {
	fps := takeoverFingerprints()
	if len(fps) < 15 {
		t.Fatalf("%d fingerprints, want the embedded list", len(fps))
	}
	fp, matched := matchTakeoverService(fps, []string{"assets-old.s3.amazonaws.com"})
	if fp == nil || fp.service != "AWS/S3" || fp.body == nil || matched != "assets-old.s3.amazonaws.com" {
		t.Fatalf("S3 = %+v", fp)
	}
	if fp, _ := matchTakeoverService(fps, []string{"app.azurewebsites.net"}); fp == nil || !fp.nxdomain {
		t.Errorf("Azure = %+v", fp)
	}
	// Suffix matches are on label boundaries.
	if fp, _ := matchTakeoverService(fps, []string{"nots3.amazonaws.com.evil.example"}); fp != nil {
		t.Errorf("matched %+v", fp)
	}
}

func TestParseTakeoverFingerprints(t *testing.T) {
	fps, err := parseTakeoverFingerprints([]byte(`[
		{"service":"A","cname":["a.example"],"fingerprint":"Not here &#124; gone","nxdomain":false,"http_status":null,"vulnerable":true},
		{"service":"B","cname":["b.example"],"fingerprint":"HTTP_STATUS=301","nxdomain":false,"http_status":301,"vulnerable":true},
		{"service":"C","cname":["c.example"],"fingerprint":"NXDOMAIN","nxdomain":true,"http_status":null,"vulnerable":true},
		{"service":"D","cname":[],"fingerprint":"404 Not Found","nxdomain":false,"http_status":null,"vulnerable":true},
		{"service":"E","cname":["e.example"],"fingerprint":"x","nxdomain":false,"http_status":null,"vulnerable":false},
		{"service":"F","cname":["f.example"],"fingerprint":"","nxdomain":false,"http_status":null,"vulnerable":true},
		{"service":"G","cname":["g.example"],"fingerprint":"bad ( regex","nxdomain":false,"http_status":null,"vulnerable":true}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fp := range fps {
		got = append(got, fmt.Sprintf("%s:%v:%d:%v", fp.service, fp.nxdomain, fp.status, fp.body))
	}
	want := `[A:false:0:Not here | gone B:false:301:<nil> C:true:0:<nil> G:false:0:bad \( regex]`
	if fmt.Sprint(got) != want {
		t.Errorf("got  %v\nwant %s", got, want)
	}
}

// nxdomainServer answers every query with NXDOMAIN.
func nxdomainServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &miekgdns.Server{PacketConn: pc, Handler: miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		m := new(miekgdns.Msg)
		m.SetRcode(r, miekgdns.RcodeNameError)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return "udp:" + pc.LocalAddr().String()
}

func TestFindTakeovers(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>")
	}))
	defer web.Close()
	bucketHost := web.Listener.Addr().String() // the "subdomain" is the test server

	s := New(Options{Resolvers: []string{nxdomainServer(t)}})
	records := []DNSRecord{
		// Points at an S3 bucket that serves S3's "no such bucket" error.
		{Host: bucketHost, Type: "CNAME", Value: "assets-old.s3.amazonaws.com."},
		{Host: bucketHost, Type: "A", Value: "127.0.0.1"},
		// Azure: unclaimed when the target doesn't exist.
		{Host: "app.example.com", Type: "CNAME", Value: "old-app.azurewebsites.net"},
		// Unknown service, target gone.
		{Host: "promo.example.com", Type: "CNAME", Value: "promo.gone-agency.example"},
		// Dangling, but inside the scanned domain: not claimable by others.
		{Host: "x.example.com", Type: "CNAME", Value: "y.example.com"},
		// No CNAME.
		{Host: "www.example.com", Type: "A", Value: "192.0.2.1"},
	}
	got, err := s.findTakeovers(t.Context(), "example.com", records)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("risks = %+v", got)
	}
	byHost := map[string]Misconfiguration{}
	for _, r := range got {
		byHost[r.host] = r.misconfig()
	}
	if r := byHost[bucketHost]; r.Check != "takeover" || r.Service != "AWS/S3" || r.Severity != "high" ||
		r.Detail != `CNAME assets-old.s3.amazonaws.com (AWS/S3) looks unclaimed: http response contains "The specified bucket does not exist"` {
		t.Errorf("S3 = %+v", r)
	}
	if r := byHost["app.example.com"]; r.Service != "Microsoft Azure" || r.Severity != "high" || r.CNAME != "old-app.azurewebsites.net" ||
		r.Detail != "CNAME old-app.azurewebsites.net (Microsoft Azure) looks unclaimed: target does not exist (NXDOMAIN)" {
		t.Errorf("Azure = %+v", r)
	}
	if r := byHost["promo.example.com"]; r.Service != "" || r.Severity != "medium" ||
		r.Detail != "CNAME promo.gone-agency.example does not exist (NXDOMAIN); check whether it can be registered or claimed" {
		t.Errorf("unknown = %+v", r)
	}
}
