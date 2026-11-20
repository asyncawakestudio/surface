// Package termui styles what the CLI prints to a terminal: the banner, log
// lines labelled [INF], [WRN] and [ERR] on stderr, and ANSI colours for the
// txt report. Colours are only used on a terminal, never in files or pipes,
// and never when NO_COLOR is set.
package termui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// Palette colours text with ANSI escapes when On, and leaves it plain
// otherwise.
type Palette struct{ On bool }

// ColorFor reports whether output to f should be coloured: f is a terminal
// and NO_COLOR (https://no-color.org) isn't set.
func ColorFor(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func (p Palette) wrap(code, s string) string {
	if !p.On || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Palette) Bold(s string) string    { return p.wrap("1", s) }
func (p Palette) Red(s string) string     { return p.wrap("31", s) }
func (p Palette) Green(s string) string   { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string  { return p.wrap("33", s) }
func (p Palette) Blue(s string) string    { return p.wrap("34", s) }
func (p Palette) Magenta(s string) string { return p.wrap("35", s) }
func (p Palette) Cyan(s string) string    { return p.wrap("36", s) }
func (p Palette) Gray(s string) string    { return p.wrap("90", s) }

// BrightRed is for the most severe findings.
func (p Palette) BrightRed(s string) string { return p.wrap("1;91", s) }

// Severity colours a CVE severity: critical bold red, high red, medium
// yellow, low green, anything else blue.
func (p Palette) Severity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return p.BrightRed(s)
	case "high":
		return p.Red(s)
	case "medium":
		return p.Yellow(s)
	case "low":
		return p.Green(s)
	}
	return p.Blue(s)
}

// Status colours an HTTP status: 2xx green, 3xx yellow, 4xx and 5xx red.
func (p Palette) Status(code int) string {
	s := fmt.Sprint(code)
	switch {
	case code >= 200 && code < 300:
		return p.Green(s)
	case code >= 300 && code < 400:
		return p.Yellow(s)
	case code >= 400:
		return p.Red(s)
	}
	return s
}

const banner = `
                    ____
   _______  _______/ __/___ _________
  / ___/ / / / ___/ /_/ __ ` + "`" + `/ ___/ _ \
 (__  ) /_/ / /  / __/ /_/ / /__/  __/
/____/\__,_/_/  /_/  \__,_/\___/\___/
`

// PrintBanner writes the banner and version, with a reminder to scan only
// what the user is authorized to.
func PrintBanner(w io.Writer, p Palette, version string) {
	fmt.Fprint(w, p.Bold(p.Cyan(banner)))
	fmt.Fprintf(w, "\t\t\tattack surface discovery %s\n\n", p.Gray(version))
	fmt.Fprintf(w, "%s Only scan domains you own or are authorized to test.\n", Label(p, slog.LevelWarn))
}

// Label is a log level's tag: [DBG], [INF], [WRN] or [ERR].
func Label(p Palette, level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "[" + p.Red("ERR") + "]"
	case level >= slog.LevelWarn:
		return "[" + p.Yellow("WRN") + "]"
	case level >= slog.LevelInfo:
		return "[" + p.Blue("INF") + "]"
	}
	return "[" + p.Magenta("DBG") + "]"
}

// Handler is a slog.Handler that writes one line per record:
// "[INF] message key=value ...".
type Handler struct {
	w     io.Writer
	p     Palette
	level slog.Level
	mu    *sync.Mutex
	attrs []slog.Attr
}

// NewHandler logs records at level or above to w.
func NewHandler(w io.Writer, p Palette, level slog.Level) *Handler {
	return &Handler{w: w, p: p, level: level, mu: &sync.Mutex{}}
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(Label(h.p, r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)
	attr := func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		v := a.Value.Resolve().String()
		if strings.ContainsAny(v, " \t\"=") {
			v = fmt.Sprintf("%q", v)
		}
		b.WriteString(" " + h.p.Gray(a.Key+"=") + v)
		return true
	}
	for _, a := range h.attrs {
		attr(a)
	}
	r.Attrs(attr)
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &c
}

// WithGroup is a no-op: surface doesn't log groups.
func (h *Handler) WithGroup(string) slog.Handler { return h }
