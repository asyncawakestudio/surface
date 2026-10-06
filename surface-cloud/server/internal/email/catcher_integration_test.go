//go:build integration

package email

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// Sends a message to a local catcher (Mailpit) to verify the "none" TLS path.
// Set SMTP_TEST_ADDR=host:port (e.g. 127.0.0.1:11025).
func TestSendToCatcher(t *testing.T) {
	addr := os.Getenv("SMTP_TEST_ADDR")
	if addr == "" {
		t.Skip("SMTP_TEST_ADDR not set")
	}
	host, port, _ := splitHostPortTest(addr)
	s := FromEnv(Config{Host: host, Port: port, From: "no-reply@surface.local", TLS: "none"}, slog.Default())
	if err := s.Send(context.Background(), "dev@example.com", "Surface login code: 123456", "Your code is 123456"); err != nil {
		t.Fatal(err)
	}
}

func splitHostPortTest(addr string) (host, port, _ string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], ""
		}
	}
	return addr, "", ""
}
