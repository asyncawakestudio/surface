//go:build !(windows && arm64)

package asm

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

func TestServiceFromNaabu(t *testing.T) {
	if serviceFromNaabu(nil) != nil {
		t.Error("nil service should map to nil")
	}
	if serviceFromNaabu(&port.Service{}) != nil {
		t.Error("a service without a name should map to nil")
	}

	got := serviceFromNaabu(&port.Service{
		Name:       "http",
		Product:    "nginx",
		Version:    "1.18.0",
		ExtraInfo:  "Ubuntu",
		Tunnel:     "ssl",
		CPEs:       []string{"cpe:/a:igor_sysoev:nginx:1.18.0/", "cpe:/o:linux:linux_kernel/"},
		Confidence: 9,
		Banner:     "HTTP/1.1 400 Bad Request",
	})
	want := Service{
		Name:      "http",
		Product:   "nginx",
		Version:   "1.18.0",
		ExtraInfo: "Ubuntu",
		TLS:       true,
		CPEs: []string{
			"cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*",
			"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
		},
		Confidence: 9,
		Banner:     "HTTP/1.1 400 Bad Request",
	}
	if got == nil || got.Name != want.Name || got.Product != want.Product || got.Version != want.Version ||
		got.ExtraInfo != want.ExtraInfo || got.TLS != want.TLS || !slices.Equal(got.CPEs, want.CPEs) ||
		got.Confidence != want.Confidence || got.Banner != want.Banner {
		t.Errorf("serviceFromNaabu = %+v,\nwant %+v", got, want)
	}
}

func TestServiceProbesFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nmap-service-probes")
	_, err := New(Options{ServiceProbesFile: missing}).serviceProbesFile()
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v, want fs.ErrNotExist", err)
	}

	if err := os.WriteFile(missing, []byte("Probe TCP NULL q||\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := New(Options{ServiceProbesFile: missing}).serviceProbesFile()
	if err != nil || got != missing {
		t.Errorf("explicit file = %q, %v; want %q, nil", got, err, missing)
	}
}

func TestRunServiceProbesNotFoundFailsEarly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nmap-service-probes")
	_, err := New(Options{PortScan: true, ServiceDetection: true, ServiceProbesFile: missing}).
		Run(t.Context(), Target{Domain: "example.com"}, nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist before any stage runs", err)
	}
}

// TestScanPortsServicesLocal runs a real naabu connect scan with service
// detection against a fake SSH server on loopback. It needs nmap's service
// probes, so it is skipped where nmap isn't installed.
func TestScanPortsServicesLocal(t *testing.T) {
	probes := fingerprint.LocateNmapProbes()
	if probes == "" {
		t.Skip("nmap-service-probes not found (install nmap)")
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"))
				buf := make([]byte, 256)
				_, _ = conn.Read(buf) // hold the connection until the prober is done
			}()
		}
	}()
	portNum := ln.Addr().(*net.TCPAddr).Port

	s := New(Options{
		PortScan:      true,
		PortScanType:  "connect",
		PortScanPorts: strconv.Itoa(portNum),
		PortScanRate:  100,
	})
	got, err := s.scanPorts(t.Context(), []resolvedHost{{Host: "localhost", IPs: []string{"127.0.0.1"}}}, probes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Ports) != 1 || got[0].Ports[0].Port != portNum {
		t.Fatalf("scanPorts = %+v, want port %d open on 127.0.0.1", got, portNum)
	}
	svc := got[0].Ports[0].Service
	if svc == nil {
		t.Fatal("no service detected on the fake SSH server")
	}
	// nmap's rule keeps the distro patch level: "8.9p1 Ubuntu 3ubuntu0.10".
	if svc.Name != "ssh" || svc.Product != "OpenSSH" || !strings.HasPrefix(svc.Version, "8.9p1") {
		t.Errorf("service = %+v, want ssh OpenSSH 8.9p1", svc)
	}
	if !slices.Contains(svc.CPEs, "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*") {
		t.Errorf("CPEs = %q, want the OpenSSH 8.9p1 CPE", svc.CPEs)
	}
	t.Logf("detected: %+v", *svc)
}
