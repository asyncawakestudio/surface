package asm

import "context"

// PortScanSupported reports whether this build includes the naabu port
// scanner. windows/arm64 builds leave it out: naabu's packet capture
// dependency (gopacket/pcap) has no windows/arm64 support.
const PortScanSupported = false

// scanPorts is unavailable on windows/arm64; Run rejects PortScan before reaching it.
func (s *Scanner) scanPorts(_ context.Context, hosts []resolvedHost) ([]PortScan, error) {
	if len(ipv4Hosts(hosts)) == 0 {
		return nil, nil
	}
	return nil, ErrPortScanUnsupported
}

func isPrivilegedScan() bool { return false }
