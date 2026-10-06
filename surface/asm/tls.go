package asm

import (
	"context"
	"strconv"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// grabCerts connects to each resolved host on the configured TLS ports and
// records the leaf certificate. Hosts that don't speak TLS are skipped.
func (s *Scanner) grabCerts(ctx context.Context, hosts []resolvedHost) ([]TLSCert, error) {
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
		for _, port := range s.opts.TLSPorts {
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
