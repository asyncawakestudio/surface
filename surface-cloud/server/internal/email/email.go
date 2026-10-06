// Package email sends transactional mail (the login codes) over SMTP. It is
// provider-agnostic: a Mailtrap/Mailjet sandbox in development and ProtonMail
// (via Proton Mail Bridge) in production are just different SMTP_* values.
package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Sender delivers a plain-text message.
type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Config is the SMTP configuration, read from the environment.
type Config struct {
	Host string
	Port string
	User string
	Pass string
	From string
	// TLS mode: "starttls" (default, e.g. port 587/2525, Proton Bridge),
	// "implicit" (TLS from connect, e.g. port 465), or "none" (plaintext, for
	// a local dev mail catcher such as Mailpit).
	TLS string
}

// FromEnv builds a Sender from the config. When Host is empty it returns a
// LogSender that writes codes to the log instead of sending — handy in dev
// before SMTP credentials are set.
func FromEnv(cfg Config, logger *slog.Logger) Sender {
	if strings.TrimSpace(cfg.Host) == "" {
		logger.Warn("email: no SMTP_HOST set; login codes will be logged, not emailed")
		return &LogSender{logger: logger}
	}
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	if cfg.From == "" {
		cfg.From = cfg.User
	}
	return &SMTPSender{cfg: cfg, logger: logger}
}

// LogSender writes the message to the log. Never use it in production.
type LogSender struct{ logger *slog.Logger }

func (l *LogSender) Send(_ context.Context, to, subject, body string) error {
	l.logger.Info("email (not sent — no SMTP configured)", "to", to, "subject", subject, "body", body)
	return nil
}

// SMTPSender sends via an SMTP server with PLAIN auth.
type SMTPSender struct {
	cfg    Config
	logger *slog.Logger
}

func (s *SMTPSender) Send(ctx context.Context, to, subject, body string) error {
	addr := net.JoinHostPort(s.cfg.Host, s.cfg.Port)
	msg := buildMessage(s.cfg.From, to, subject, body)
	auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Pass, s.cfg.Host)

	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}

	if s.cfg.TLS == "implicit" {
		conn = tls.Client(conn, &tls.Config{ServerName: s.cfg.Host})
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	switch s.cfg.TLS {
	case "implicit", "none":
		// implicit was wrapped before NewClient; none stays plaintext.
	default: // starttls
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		} else if !isLoopback(s.cfg.Host) {
			return fmt.Errorf("smtp: server does not support STARTTLS and host is not loopback (use SMTP_TLS=none for a local mail catcher)")
		}
	}

	if s.cfg.User != "" {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return c.Quit()
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
