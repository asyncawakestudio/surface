package asm

import (
	"slices"
	"strconv"
	"strings"
)

// Diff describes what changed between two scans of the same domain.
type Diff struct {
	Subdomains SubdomainDiff      `json:"subdomains"`
	DNSRecords SetDiff[DNSRecord] `json:"dns_records"`
	TLSCerts   CertDiff           `json:"tls_certs"`
}

// SetDiff lists items present in only one of two scans.
type SetDiff[T any] struct {
	Added   []T `json:"added"`
	Removed []T `json:"removed"`
}

// SubdomainDiff also reports hosts that sources stopped returning. Since
// subdomains are append-only these stay in the scan as carried over, so they
// don't show up as Removed.
type SubdomainDiff struct {
	SetDiff[Subdomain]
	NoLongerReported []Subdomain `json:"no_longer_reported"`
}

// CertDiff also reports endpoints whose certificate was replaced.
type CertDiff struct {
	SetDiff[TLSCert]
	Changed []CertChange `json:"changed"`
}

// CertChange is an endpoint (host:port) that presented a different
// certificate in the newer scan.
type CertChange struct {
	Before TLSCert `json:"before"`
	After  TLSCert `json:"after"`
}

// Empty reports whether nothing changed.
func (d Diff) Empty() bool {
	return len(d.Subdomains.Added)+len(d.Subdomains.Removed)+len(d.Subdomains.NoLongerReported)+
		len(d.DNSRecords.Added)+len(d.DNSRecords.Removed)+
		len(d.TLSCerts.Added)+len(d.TLSCerts.Removed)+len(d.TLSCerts.Changed) == 0
}

// Compare returns the changes from prev to cur. Subdomains are compared by
// host, DNS records by (host, type, value) and certificates by endpoint,
// with a changed fingerprint counting as a replaced certificate.
func Compare(prev, cur *Result) Diff {
	d := Diff{
		Subdomains: SubdomainDiff{
			SetDiff:          setDiff(prev.Subdomains, cur.Subdomains, func(s Subdomain) string { return s.Host }),
			NoLongerReported: []Subdomain{},
		},
		DNSRecords: setDiff(prev.DNSRecords, cur.DNSRecords, func(r DNSRecord) string {
			return r.Host + "\x00" + r.Type + "\x00" + r.Value
		}),
	}

	reportedBefore := make(map[string]bool, len(prev.Subdomains))
	for _, sd := range prev.Subdomains {
		if !sd.CarriedOver {
			reportedBefore[sd.Host] = true
		}
	}
	for _, sd := range cur.Subdomains {
		if sd.CarriedOver && reportedBefore[sd.Host] {
			d.Subdomains.NoLongerReported = append(d.Subdomains.NoLongerReported, sd)
		}
	}

	endpoint := func(c TLSCert) string { return c.Host + ":" + strconv.Itoa(c.Port) }
	d.TLSCerts.SetDiff = setDiff(prev.TLSCerts, cur.TLSCerts, endpoint)
	d.TLSCerts.Changed = []CertChange{}

	before := make(map[string]TLSCert, len(prev.TLSCerts))
	for _, c := range prev.TLSCerts {
		before[endpoint(c)] = c
	}
	for _, c := range cur.TLSCerts {
		if old, ok := before[endpoint(c)]; ok && old.FingerprintSHA256 != c.FingerprintSHA256 {
			d.TLSCerts.Changed = append(d.TLSCerts.Changed, CertChange{Before: old, After: c})
		}
	}
	slices.SortFunc(d.TLSCerts.Changed, func(a, b CertChange) int {
		return strings.Compare(endpoint(a.After), endpoint(b.After))
	})
	return d
}

func setDiff[T any](prev, cur []T, key func(T) string) SetDiff[T] {
	inPrev := make(map[string]bool, len(prev))
	for _, v := range prev {
		inPrev[key(v)] = true
	}
	inCur := make(map[string]bool, len(cur))
	for _, v := range cur {
		inCur[key(v)] = true
	}

	d := SetDiff[T]{Added: []T{}, Removed: []T{}}
	for _, v := range cur {
		if !inPrev[key(v)] {
			d.Added = append(d.Added, v)
		}
	}
	for _, v := range prev {
		if !inCur[key(v)] {
			d.Removed = append(d.Removed, v)
		}
	}
	byKey := func(a, b T) int { return strings.Compare(key(a), key(b)) }
	slices.SortFunc(d.Added, byKey)
	slices.SortFunc(d.Removed, byKey)
	return d
}
