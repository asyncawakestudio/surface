package asm

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestProbeWeb(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title> Example Blog </title>
<meta name="generator" content="WordPress 6.4.1" />
<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body>hi</body></html>`)
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := New(Options{})
	pages, err := s.probeWeb(t.Context(), []string{"127.0.0.1:" + portStr})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 {
		t.Fatalf("pages = %+v", pages)
	}
	p := pages[0]
	t.Logf("%+v", p)
	if p.URL != "http://127.0.0.1:"+portStr || p.Port != port || p.Scheme != "http" || p.StatusCode != 200 ||
		p.Title != "Example Blog" || p.Host != "127.0.0.1" || p.WebServer != "nginx/1.18.0" {
		t.Errorf("page = %+v", p)
	}
	var wp *Technology
	for i, tech := range p.Technologies {
		if tech.Name == "WordPress" {
			wp = &p.Technologies[i]
		}
	}
	if wp == nil || wp.Version != "6.4.1" || wp.CPE != "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*" {
		t.Fatalf("WordPress = %+v in %+v", wp, p.Technologies)
	}

	svcs := webServices(pages)
	found := false
	for _, s := range svcs {
		if s.Service.Product == "WordPress" && s.Port == port && s.Hosts[0] == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("webServices = %+v", svcs)
	}
}

func TestWebTargets(t *testing.T) {
	s := New(Options{})
	hosts := []resolvedHost{{Host: "a.example.com", IPs: []string{"192.0.2.1"}}, {Host: "b.example.com", IPs: []string{"192.0.2.2"}}}
	got := s.webTargets(hosts, nil, false)
	want := []string{"a.example.com:80", "a.example.com:443", "b.example.com:80", "b.example.com:443"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("without port scan = %v, want %v", got, want)
	}

	scans := []PortScan{{IP: "192.0.2.1", Ports: []OpenPort{
		{Port: 22, Protocol: "tcp", Service: &Service{Name: "ssh"}},
		{Port: 443, Protocol: "tcp", Service: &Service{Name: "http", TLS: true}},
		{Port: 8080, Protocol: "tcp"},
		{Port: 8443, Protocol: "tcp", Service: &Service{Name: "https-alt"}},
	}}}
	got = s.webTargets(hosts, scans, true)
	want = []string{"a.example.com:443", "a.example.com:8080", "a.example.com:8443"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("with port scan = %v, want %v", got, want)
	}
}

func TestCPEWithVersion(t *testing.T) {
	for _, tc := range []struct{ cpe, version, want string }{
		{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "6.4.1", "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*"},
		{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "", "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
		{"cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*", "2.0", "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"},
	} {
		if got := cpeWithVersion(tc.cpe, tc.version); got != tc.want {
			t.Errorf("cpeWithVersion(%q, %q) = %q, want %q", tc.cpe, tc.version, got, tc.want)
		}
	}
}

func TestVulnTargets(t *testing.T) {
	const nginx = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
	services := []ServiceTarget{{IP: "192.0.2.1", Hosts: []string{"a.example.com"}, Port: 443, Protocol: "tcp",
		Service: Service{Name: "http", Product: "nginx", Version: "1.18.0", CPEs: []string{nginx}}}}
	tech := func(name, version, cpe string) []Technology {
		return []Technology{{Name: name, Version: version, CPE: cpe}}
	}
	pages := []WebPage{
		{Host: "a.example.com", IP: "192.0.2.1", Port: 443, Scheme: "https", Technologies: tech("Nginx", "1.18.0", nginx)},
		{Host: "b.example.com", IP: "192.0.2.1", Port: 443, Scheme: "https", Technologies: tech("Nginx", "1.18.0", nginx)},
		{Host: "b.example.com", IP: "192.0.2.1", Port: 443, Scheme: "https",
			Technologies: tech("WordPress", "6.4.1", "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*")},
		{Host: "c.example.com", IP: "192.0.2.1", Port: 443, Scheme: "https",
			Technologies: tech("WordPress", "6.4.1", "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*")},
		{Host: "d.example.com", IP: "192.0.2.1", Port: 443, Scheme: "https", Technologies: tech("PHP", "", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")},
	}
	got := vulnTargets(services, pages)
	if len(got) != 2 {
		t.Fatalf("vulnTargets = %+v", got)
	}
	if fmt.Sprint(got[0].Hosts) != "[a.example.com b.example.com]" {
		t.Errorf("nginx hosts = %v", got[0].Hosts)
	}
	if got[1].Service.Product != "WordPress" || fmt.Sprint(got[1].Hosts) != "[b.example.com c.example.com]" {
		t.Errorf("wordpress = %+v", got[1])
	}
	if fmt.Sprint(services[0].Hosts) != "[a.example.com]" {
		t.Errorf("input modified: %v", services[0].Hosts)
	}
}

func TestCompareWeb(t *testing.T) {
	page := func(url string, status int, title string, techs ...Technology) WebPage {
		return WebPage{URL: url, StatusCode: status, Title: title, Technologies: techs}
	}
	prev := &Result{Stages: []Stage{StageWeb}, Web: []WebPage{
		page("https://api.example.com", 401, "Unauthorized"),
		page("https://www.example.com", 200, "Home", Technology{Name: "WordPress", Version: "6.4.1"}),
		page("https://old.example.com", 200, "Old"),
	}}
	cur := &Result{Stages: []Stage{StageWeb}, Web: []WebPage{
		page("https://api.example.com", 200, "API docs"),
		page("https://www.example.com", 200, "Home", Technology{Name: "WordPress", Version: "6.5"}),
		page("https://new.example.com", 200, "New"),
	}}
	d := Compare(prev, cur).Web
	if !d.Compared || len(d.Added) != 1 || d.Added[0].URL != "https://new.example.com" ||
		len(d.Removed) != 1 || d.Removed[0].URL != "https://old.example.com" {
		t.Fatalf("diff = %+v", d)
	}
	want := `[{https://api.example.com [{status_code 401 200} {title Unauthorized API docs}]} {https://www.example.com [{technologies WordPress 6.4.1 WordPress 6.5}]}]`
	if got := fmt.Sprint(d.Changed); got != want {
		t.Errorf("changed = %s\nwant      %s", got, want)
	}

	// Without a baseline, every page would look new.
	if d := Compare(&Result{Stages: []Stage{StageDNS}}, cur); d.Web.Compared || !d.Empty() {
		t.Errorf("diff = %+v", d.Web)
	}
}
