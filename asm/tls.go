package asm

import (
	"context"
	"slices"
	"strconv"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// grabCerts connects to each resolved host on the configured TLS ports, plus
// the host's ports in extraPorts, and records the leaf certificate. Hosts
// that don't speak TLS are skipped.
func (s *Scanner) grabCerts(ctx context.Context, hosts []resolvedHost, extraPorts map[string][]int) ([]TLSCert, error) {
	svc, err := tlsx.New(&clients.Options{
		ScanMode:    "auto",
		Timeout:     int(s.opts.TLSTimeout.Seconds()),
		Retries:     1,
		Concurrency: s.opts.TLSConcurrency,
	})
	if err != nil {
		return nil, err
	}

	type target struct {
		host, ip string
		port     int
	}
	var targets []target
	for _, h := range hosts {
		ports := slices.Clone(s.opts.TLSPorts)
		for _, p := range extraPorts[h.Host] {
			if !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
		for _, port := range ports {
			targets = append(targets, target{host: h.Host, ip: h.IPs[0], port: port})
		}
	}

	certs := make([]*TLSCert, len(targets))
	forEach(ctx, targets, s.opts.TLSConcurrency, func(i int, t target) {
		resp, err := svc.ConnectWithOptions(t.host, t.ip, strconv.Itoa(t.port), clients.ConnectOptions{SNI: t.host})
		if err != nil || resp == nil || resp.CertificateResponse == nil {
			return
		}
		c := resp.CertificateResponse
		certs[i] = &TLSCert{
			Host:              t.host,
			IP:                t.ip,
			Port:              t.port,
			TLSVersion:        resp.Version,
			Cipher:            resp.Cipher,
			SubjectCN:         c.SubjectCN,
			SubjectOrg:        c.SubjectOrg,
			SANs:              c.SubjectAN,
			IssuerCN:          c.IssuerCN,
			IssuerOrg:         c.IssuerOrg,
			Serial:            c.Serial,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			Expired:           c.Expired,
			SelfSigned:        c.SelfSigned,
			Mismatched:        c.MisMatched,
			Wildcard:          c.WildCardCert,
			FingerprintSHA256: c.FingerprintHash.SHA256,
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var out []TLSCert
	for _, c := range certs {
		if c != nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

// tlsPortsByHost lists, per host, the ports beyond Options.TLSPorts where TLS
// was seen: HTTPS pages from the web stage, and open ports where service
// detection found TLS on one of the host's IPs.
func tlsPortsByHost(hosts []resolvedHost, scans []PortScan, pages []WebPage) map[string][]int {
	tlsByIP := map[string][]int{}
	for _, ps := range scans {
		for _, p := range ps.Ports {
			if p.Protocol == "tcp" && p.Service != nil && p.Service.TLS {
				tlsByIP[ps.IP] = append(tlsByIP[ps.IP], p.Port)
			}
		}
	}
	out := map[string][]int{}
	add := func(host string, port int) {
		if !slices.Contains(out[host], port) {
			out[host] = append(out[host], port)
		}
	}
	for _, h := range hosts {
		for _, ip := range h.IPs {
			for _, p := range tlsByIP[ip] {
				add(h.Host, p)
			}
		}
	}
	for _, p := range pages {
		if p.Scheme == "https" {
			add(p.Host, p.Port)
		}
	}
	for h := range out {
		slices.Sort(out[h])
	}
	return out
}
