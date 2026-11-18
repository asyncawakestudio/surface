package asm

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// PortDiff lists ports that opened or closed and ports whose service changed.
type PortDiff struct {
	// Compared is false unless both scans ran the port scan; without a
	// baseline every port would look new.
	Compared bool `json:"compared"`
	SetDiff[PortEntry]
	// ServiceChanged lists open ports whose identified service differs (new
	// product, version or TLS). Ports identified in only one of the scans are
	// not listed, since detection can miss a service from one run to the next.
	// It is empty unless both scans ran service detection.
	ServiceChanged []ServiceChange `json:"service_changed"`
}

// PortEntry is one open port on an IP.
type PortEntry struct {
	IP    string   `json:"ip"`
	Hosts []string `json:"hosts"`
	OpenPort
}

// ServiceChange is an open port whose service differs between two scans.
type ServiceChange struct {
	IP       string  `json:"ip"`
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	Before   Service `json:"before"`
	After    Service `json:"after"`
}

// VulnDiff lists CVEs that newly affect, or no longer affect, a service.
type VulnDiff struct {
	// Compared is false unless both scans ran the vulnerability lookup.
	Compared bool `json:"compared"`
	SetDiff[VulnEntry]
}

// VulnEntry is one CVE matched to the service on one port.
type VulnEntry struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	// CPE is the versioned CPE the CVE was matched on.
	CPE string `json:"cpe"`
	Vulnerability
}

// ran reports whether stage ran in r. Results saved before Result.Stages
// existed are judged by their data: a stage that found nothing looks like one
// that never ran.
func (r *Result) ran(stage Stage) bool {
	if len(r.Stages) > 0 {
		return slices.Contains(r.Stages, stage)
	}
	switch stage {
	case StagePorts:
		return len(r.PortScans) > 0
	case StageServices:
		return len(r.Services()) > 0
	case StageVulns:
		return len(r.Vulnerabilities) > 0
	}
	return false
}

func comparePorts(prev, cur *Result) PortDiff {
	d := PortDiff{
		SetDiff:        SetDiff[PortEntry]{Added: []PortEntry{}, Removed: []PortEntry{}},
		ServiceChanged: []ServiceChange{},
	}
	if !prev.ran(StagePorts) || !cur.ran(StagePorts) {
		return d
	}
	d.Compared = true
	key := func(p PortEntry) string { return portKey(p.IP, p.Port, p.Protocol) }
	d.SetDiff = setDiff(portEntries(prev), portEntries(cur), key)

	if !prev.ran(StageServices) || !cur.ran(StageServices) {
		return d
	}
	before := map[string]Service{}
	for _, s := range prev.Services() {
		before[portKey(s.IP, s.Port, s.Protocol)] = s.Service
	}
	for _, s := range cur.Services() {
		old, ok := before[portKey(s.IP, s.Port, s.Protocol)]
		if ok && !sameService(old, s.Service) {
			d.ServiceChanged = append(d.ServiceChanged, ServiceChange{
				IP: s.IP, Port: s.Port, Protocol: s.Protocol, Before: old, After: s.Service,
			})
		}
	}
	slices.SortFunc(d.ServiceChanged, func(a, b ServiceChange) int {
		return strings.Compare(portKey(a.IP, a.Port, a.Protocol), portKey(b.IP, b.Port, b.Protocol))
	})
	return d
}

func compareVulnerabilities(prev, cur *Result) VulnDiff {
	d := VulnDiff{SetDiff: SetDiff[VulnEntry]{Added: []VulnEntry{}, Removed: []VulnEntry{}}}
	if !prev.ran(StageVulns) || !cur.ran(StageVulns) {
		return d
	}
	d.Compared = true
	d.SetDiff = setDiff(vulnEntries(prev), vulnEntries(cur), func(v VulnEntry) string {
		return portKey(v.IP, v.Port, v.Protocol) + "\x00" + v.ID
	})
	// Most urgent first, like the scan itself.
	byUrgency := func(a, b VulnEntry) int {
		return cmp.Or(compareVulns(a.Vulnerability, b.Vulnerability),
			strings.Compare(portKey(a.IP, a.Port, a.Protocol), portKey(b.IP, b.Port, b.Protocol)))
	}
	slices.SortFunc(d.Added, byUrgency)
	slices.SortFunc(d.Removed, byUrgency)
	return d
}

func portEntries(r *Result) []PortEntry {
	var out []PortEntry
	for _, ps := range r.PortScans {
		for _, p := range ps.Ports {
			out = append(out, PortEntry{IP: ps.IP, Hosts: ps.Hosts, OpenPort: p})
		}
	}
	return out
}

// vulnEntries flattens r's vulnerabilities, one per port and CVE. A service
// with several CPEs can match the same CVE more than once; it is kept once.
func vulnEntries(r *Result) []VulnEntry {
	var out []VulnEntry
	seen := map[string]bool{}
	for _, sv := range r.Vulnerabilities {
		for _, v := range sv.Vulnerabilities {
			k := portKey(sv.IP, sv.Port, sv.Protocol) + "\x00" + v.ID
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, VulnEntry{IP: sv.IP, Port: sv.Port, Protocol: sv.Protocol, CPE: sv.CPE, Vulnerability: v})
		}
	}
	return out
}

// portKey sorts by IP, then numerically by port.
func portKey(ip string, port int, protocol string) string {
	return ip + "\x00" + strconv.Itoa(100000+port) + "/" + protocol
}

// sameService reports whether two detections name the same service. Banner,
// confidence and extra info vary between probes and are ignored.
func sameService(a, b Service) bool {
	return a.Name == b.Name && a.Product == b.Product && a.Version == b.Version && a.TLS == b.TLS
}
