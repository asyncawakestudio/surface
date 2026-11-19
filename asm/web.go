package asm

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// WebPage is what a host serves over HTTP(S) on one port. A single IP and port
// can serve many sites (virtual hosts), so pages are per host, not per IP.
type WebPage struct {
	// URL is the probed URL, e.g. "https://www.example.com".
	URL    string `json:"url"`
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	// StatusCode is the response status. Redirects are not followed.
	StatusCode int `json:"status_code"`
	// Location is the redirect target, for 3xx responses.
	Location      string `json:"location,omitempty"`
	Title         string `json:"title,omitempty"`
	WebServer     string `json:"web_server,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int    `json:"content_length"`
	// Technologies are detected from the response (Wappalyzer fingerprints).
	Technologies []Technology `json:"technologies,omitempty"`
	// CDN is the CDN or WAF in front of the site, e.g. "cloudflare".
	CDN string `json:"cdn,omitempty"`
	// CDNType is "cdn" or "waf".
	CDNType string `json:"cdn_type,omitempty"`
}

// Technology is a product detected on a web page.
type Technology struct {
	Name string `json:"name"`
	// Version is empty when the page doesn't reveal it.
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	// CPE is set when the product has a known CPE; it names the version when
	// Version is known, so the vulns stage can look it up.
	CPE string `json:"cpe,omitempty"`
}

// webTargets lists the host:port pairs to probe. With a port scan, every open
// TCP port on the host's IPv4 addresses is probed, except ports where service
// detection found something other than HTTP. Without one, WebPorts are probed.
func (s *Scanner) webTargets(hosts []resolvedHost, scans []PortScan, portScanned bool) []string {
	open := map[string][]OpenPort{}
	for _, ps := range scans {
		open[ps.IP] = ps.Ports
	}
	var out []string
	seen := map[string]bool{}
	add := func(host string, port int) {
		t := host + ":" + strconv.Itoa(port)
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, h := range hosts {
		if !portScanned {
			for _, p := range s.opts.WebPorts {
				add(h.Host, p)
			}
			continue
		}
		for _, ip := range h.IPs {
			for _, p := range open[ip] {
				if p.Protocol == "tcp" && mayServeHTTP(p.Service) {
					add(h.Host, p.Port)
				}
			}
		}
	}
	return out
}

// mayServeHTTP reports whether a port may serve HTTP: its service is unknown,
// or was identified as an HTTP service (http, https, http-proxy...).
func mayServeHTTP(svc *Service) bool {
	return svc == nil || svc.Name == "" || strings.Contains(svc.Name, "http")
}

// probeWeb requests each target over HTTPS, falling back to HTTP, and records
// what it serves.
func (s *Scanner) probeWeb(ctx context.Context, targets []string) ([]WebPage, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	var (
		mu    sync.Mutex
		pages []WebPage
	)
	options := runner.Options{
		InputTargetHost:           goflags.StringSlice(targets),
		Methods:                   "GET",
		Threads:                   s.opts.WebConcurrency,
		Timeout:                   int(s.opts.WebTimeout.Seconds()),
		Retries:                   1,
		ExtractTitle:              true,
		StatusCode:                true,
		Location:                  true,
		ContentLength:             true,
		OutputContentType:         true,
		OutputServerHeader:        true,
		OutputIP:                  true,
		TechDetect:                true,
		OutputCDN:                 "true",
		RandomAgent:               true,
		HostMaxErrors:             -1,
		MaxResponseBodySizeToRead: 2 << 20,
		DisableStdout:             true,
		DisableStdin:              true,
		Silent:                    true,
		NoColor:                   true,
		DisableUpdateCheck:        true,
		OnResult: func(r runner.Result) {
			if r.Err != nil || r.Failed {
				return
			}
			page := webPageFromHTTPX(r)
			mu.Lock()
			pages = append(pages, page)
			mu.Unlock()
		},
	}
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("httpx options: %w", err)
	}
	r, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("httpx init: %w", err)
	}

	s.opts.Logger.Info("web: probing", "targets", len(targets))
	// httpx has no context support: on cancellation, stop waiting and let the
	// in-flight requests finish in the background.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.Close()
		r.RunEnumeration()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}

	slices.SortFunc(pages, func(a, b WebPage) int {
		return cmpString(webPageKey(a), webPageKey(b))
	})
	// httpx reports a target once per scheme that answered; drop repeats.
	pages = slices.CompactFunc(pages, func(a, b WebPage) bool { return a.URL == b.URL })
	return pages, nil
}

func webPageFromHTTPX(r runner.Result) WebPage {
	port, _ := strconv.Atoi(r.Port)
	host := r.Input
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	return WebPage{
		URL:           r.URL,
		Host:          host,
		IP:            r.HostIP,
		Port:          port,
		Scheme:        r.Scheme,
		StatusCode:    r.StatusCode,
		Location:      r.Location,
		Title:         strings.TrimSpace(r.Title),
		WebServer:     r.WebServer,
		ContentType:   r.ContentType,
		ContentLength: r.ContentLength,
		Technologies:  technologies(r.TechnologyDetails),
		CDN:           r.CDNName,
		CDNType:       r.CDNType,
	}
}

// technologies converts Wappalyzer matches ("WordPress:6.4.1" -> AppInfo).
func technologies(matches map[string]wappalyzer.AppInfo) []Technology {
	out := make([]Technology, 0, len(matches))
	for match, info := range matches {
		name, version, _ := strings.Cut(match, ":")
		t := Technology{Name: name, Version: version, Categories: info.Categories}
		if cpe, ok := CPE23(info.CPE); ok {
			t.CPE = cpeWithVersion(cpe, version)
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b Technology) int { return cmpString(a.Name, b.Name) })
	if len(out) == 0 {
		return nil
	}
	return out
}

// cpeWithVersion fills a CPE 2.3 name's version field, if it has none.
func cpeWithVersion(cpe, version string) string {
	if version == "" {
		return cpe
	}
	fields := splitCPE23(strings.TrimPrefix(cpe, "cpe:2.3:"))
	if fields[3] != "*" && fields[3] != "-" {
		return cpe
	}
	fields[3] = escapeCPE23(strings.ToLower(version))
	return "cpe:2.3:" + strings.Join(fields, ":")
}

// vulnTargets combines the port scan's services with the web stage's
// versioned technologies for the vulns stage. A product seen on the same IP and
// port by both, or by several hosts sharing it, is listed once.
func vulnTargets(services []ServiceTarget, pages []WebPage) []ServiceTarget {
	out := slices.Clone(services)
	index := map[string]int{} // IP, port and CPE -> position in out
	for i, s := range services {
		for _, cpe := range s.Service.CPEs {
			index[portKey(s.IP, s.Port, s.Protocol)+"\x00"+cpe] = i
		}
	}
	for _, w := range webServices(pages) {
		k := portKey(w.IP, w.Port, w.Protocol) + "\x00" + w.Service.CPEs[0]
		if i, ok := index[k]; ok {
			for _, h := range w.Hosts {
				if !slices.Contains(out[i].Hosts, h) {
					out[i].Hosts = append(slices.Clip(out[i].Hosts), h)
				}
			}
			continue
		}
		index[k] = len(out)
		out = append(out, w)
	}
	return out
}

// webServices turns the technologies detected with a version into services.
func webServices(pages []WebPage) []ServiceTarget {
	var out []ServiceTarget
	for _, p := range pages {
		for _, t := range p.Technologies {
			if t.CPE == "" || !cpeHasVersion(t.CPE) {
				continue
			}
			out = append(out, ServiceTarget{
				IP:       p.IP,
				Hosts:    []string{p.Host},
				Port:     p.Port,
				Protocol: "tcp",
				Service: Service{
					Name:    p.Scheme,
					Product: t.Name,
					Version: t.Version,
					TLS:     p.Scheme == "https",
					CPEs:    []string{t.CPE},
				},
			})
		}
	}
	return out
}

// webPageKey orders pages by host, then port, then URL.
func webPageKey(p WebPage) string {
	return p.Host + "\x00" + strconv.Itoa(100000+p.Port) + "\x00" + p.URL
}
