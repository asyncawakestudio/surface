package asm

import "testing"

func TestComparePorts(t *testing.T) {
	ssh := func(version string) *Service {
		return &Service{Name: "ssh", Product: "OpenSSH", Version: version, Banner: "SSH-2.0-" + version}
	}
	prev := &Result{
		Stages: []Stage{StagePorts, StageServices},
		PortScans: []PortScan{{IP: "192.0.2.1", Hosts: []string{"a.example.com"}, Ports: []OpenPort{
			{Port: 22, Protocol: "tcp", Service: ssh("8.9p1")},
			{Port: 80, Protocol: "tcp"},
			{Port: 8080, Protocol: "tcp", Service: &Service{Name: "http", Confidence: 5}},
		}}},
	}
	cur := &Result{
		Stages: []Stage{StagePorts, StageServices},
		PortScans: []PortScan{{IP: "192.0.2.1", Hosts: []string{"a.example.com"}, Ports: []OpenPort{
			{Port: 22, Protocol: "tcp", Service: ssh("9.6p1")},
			{Port: 443, Protocol: "tcp"},
			// Only banner-level details changed: not a service change.
			{Port: 8080, Protocol: "tcp", Service: &Service{Name: "http", Confidence: 10}},
		}}},
	}

	d := Compare(prev, cur).Ports
	if !d.Compared {
		t.Fatal("Compared = false")
	}
	if len(d.Added) != 1 || d.Added[0].Port != 443 || d.Added[0].IP != "192.0.2.1" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Port != 80 {
		t.Errorf("removed = %+v", d.Removed)
	}
	if len(d.ServiceChanged) != 1 || d.ServiceChanged[0].Port != 22 ||
		d.ServiceChanged[0].Before.Version != "8.9p1" || d.ServiceChanged[0].After.Version != "9.6p1" {
		t.Errorf("service changed = %+v", d.ServiceChanged)
	}

	// Without service detection in the older scan, services aren't compared.
	prev.Stages = []Stage{StagePorts}
	if d := Compare(prev, cur).Ports; len(d.ServiceChanged) != 0 || len(d.Added) != 1 {
		t.Errorf("diff = %+v", d)
	}
}

func TestComparePortsWithoutBaseline(t *testing.T) {
	cur := &Result{
		Stages:    []Stage{StagePorts},
		PortScans: []PortScan{{IP: "192.0.2.1", Ports: []OpenPort{{Port: 22, Protocol: "tcp"}}}},
	}
	// The older scan didn't scan ports, so 22 isn't newly open.
	if d := Compare(&Result{Stages: []Stage{StageDNS}}, cur); d.Ports.Compared || !d.Empty() {
		t.Errorf("diff = %+v", d.Ports)
	}
	// A port scan that found nothing is a baseline.
	d := Compare(&Result{Stages: []Stage{StagePorts}}, cur)
	if !d.Ports.Compared || len(d.Ports.Added) != 1 {
		t.Errorf("diff = %+v", d.Ports)
	}
	// Results saved before Stages existed are judged by their data.
	if d := Compare(&Result{}, cur); d.Ports.Compared {
		t.Errorf("diff = %+v", d.Ports)
	}
	if d := Compare(&Result{PortScans: cur.PortScans}, cur); !d.Ports.Compared || !d.Empty() {
		t.Errorf("diff = %+v", d.Ports)
	}
}

func TestCompareVulnDiff(t *testing.T) {
	target := ServiceTarget{IP: "192.0.2.1", Port: 22, Protocol: "tcp"}
	const cpe = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
	prev := &Result{
		Stages: []Stage{StagePorts, StageServices, StageVulns},
		Vulnerabilities: []ServiceVulnerabilities{{ServiceTarget: target, CPE: cpe, Vulnerabilities: []Vulnerability{
			{ID: "CVE-2023-38408", Severity: "critical"},
			{ID: "CVE-2021-0001", Severity: "low"},
		}}},
	}
	cur := &Result{
		Stages: []Stage{StagePorts, StageServices, StageVulns},
		Vulnerabilities: []ServiceVulnerabilities{{ServiceTarget: target, CPE: cpe, Vulnerabilities: []Vulnerability{
			{ID: "CVE-2023-38408", Severity: "critical"},
			{ID: "CVE-2024-0002", Severity: "medium"},
			{ID: "CVE-2024-0003", Severity: "high", KEV: true},
		}}},
	}

	d := Compare(prev, cur).Vulns
	if !d.Compared {
		t.Fatal("Compared = false")
	}
	// Most urgent first.
	if len(d.Added) != 2 || d.Added[0].ID != "CVE-2024-0003" || d.Added[1].ID != "CVE-2024-0002" ||
		d.Added[0].Port != 22 || d.Added[0].CPE != cpe {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].ID != "CVE-2021-0001" {
		t.Errorf("removed = %+v", d.Removed)
	}

	// The older scan didn't look up CVEs: nothing is newly vulnerable.
	prev.Stages = []Stage{StagePorts, StageServices}
	if d := Compare(prev, cur).Vulns; d.Compared || len(d.Added) != 0 {
		t.Errorf("diff = %+v", d)
	}
}
