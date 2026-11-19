package asm

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	miekgdns "github.com/miekg/dns"
)

// bruteZone answers A queries from hosts (name -> IP). With wildcardIP set,
// every other name under the zone resolves to it; otherwise they don't exist.
func bruteZone(t *testing.T, hosts map[string]string, wildcardIP string) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &miekgdns.Server{PacketConn: pc, Handler: miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		m := new(miekgdns.Msg)
		m.SetReply(r)
		ip, ok := hosts[name]
		if !ok && wildcardIP != "" {
			ip, ok = wildcardIP, true
		}
		switch {
		case !ok:
			m.SetRcode(r, miekgdns.RcodeNameError)
		case q.Qtype == miekgdns.TypeA:
			rr, _ := miekgdns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip))
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return "udp:" + pc.LocalAddr().String()
}

func writeWordlist(t *testing.T, words ...string) string {
	p := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(p, []byte(strings.Join(words, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBruteforceSubdomains(t *testing.T) {
	resolver := bruteZone(t, map[string]string{
		"dev.example.com":     "192.0.2.10",
		"vpn.example.com":     "192.0.2.11",
		"mail.example.com":    "192.0.2.12",
		"a.b.example.com":     "192.0.2.13",
		"staging.example.com": "192.0.2.14",
	}, "")
	s := New(Options{Resolvers: []string{resolver}, SubdomainWordlist: writeWordlist(t,
		"dev", "VPN", "vpn", "nope", "a.b", "bad label", "-x", "", "# comment", "mail", "staging")})
	got, err := s.bruteforceSubdomains(t.Context(), "example.com", map[string]bool{"mail.example.com": true})
	if err != nil {
		t.Fatal(err)
	}
	// mail is already known; nope doesn't exist; invalid labels are skipped.
	if want := "[dev.example.com vpn.example.com a.b.example.com staging.example.com]"; fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestBruteforceSubdomainsWildcard(t *testing.T) {
	// Every name resolves to 192.0.2.99; only dev has its own address.
	resolver := bruteZone(t, map[string]string{"dev.example.com": "192.0.2.10"}, "192.0.2.99")
	s := New(Options{Resolvers: []string{resolver}, SubdomainWordlist: writeWordlist(t, "dev", "www", "anything")})
	got, err := s.bruteforceSubdomains(t.Context(), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[dev.example.com]" {
		t.Errorf("got %v, want only dev.example.com", got)
	}
}

func TestSubdomainWordlist(t *testing.T) {
	words, err := New(Options{}).subdomainWordlist()
	if err != nil {
		t.Fatal(err)
	}
	if len(words) < 4500 || words[0] != "www" {
		t.Errorf("default wordlist: %d words, first %q", len(words), words[0])
	}
	if _, err := New(Options{SubdomainWordlist: writeWordlist(t, "!!", "")}).subdomainWordlist(); err == nil {
		t.Error("wordlist without valid entries accepted")
	}
	if _, err := New(Options{SubdomainWordlist: filepath.Join(t.TempDir(), "missing")}).subdomainWordlist(); err == nil {
		t.Error("missing wordlist accepted")
	}
}
