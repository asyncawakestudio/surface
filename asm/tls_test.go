package asm

import (
	"fmt"
	"testing"
)

func TestTLSPortsByHost(t *testing.T) {
	hosts := []resolvedHost{{Host: "a.example.com", IPs: []string{"192.0.2.1"}}, {Host: "b.example.com", IPs: []string{"192.0.2.2"}}}
	scans := []PortScan{{IP: "192.0.2.1", Ports: []OpenPort{
		{Port: 22, Protocol: "tcp", Service: &Service{Name: "ssh"}},
		{Port: 993, Protocol: "tcp", Service: &Service{Name: "imap", TLS: true}},
		{Port: 8443, Protocol: "tcp", Service: &Service{Name: "http", TLS: true}},
	}}}
	pages := []WebPage{
		{Host: "b.example.com", Port: 9443, Scheme: "https"},
		{Host: "b.example.com", Port: 8080, Scheme: "http"},
		{Host: "a.example.com", Port: 8443, Scheme: "https"},
	}
	got := tlsPortsByHost(hosts, scans, pages)
	if want := "map[a.example.com:[993 8443] b.example.com:[9443]]"; fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
