// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package security provides host-level port detection and analysis.
package security

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// HostPortScanner provides host-level port scanning capabilities
type HostPortScanner struct {
	logger *logger.Logger
}

// NewHostPortScanner creates a new host port scanner
func NewHostPortScanner(log *logger.Logger) *HostPortScanner {
	return &HostPortScanner{
		logger: log.Named("port-scanner"),
	}
}

// OpenPort represents an open port on the host
type OpenPort struct {
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol"` // tcp, tcp6, udp, udp6
	LocalAddr string `json:"local_addr"`
	State     string `json:"state"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
	UID       int    `json:"uid,omitempty"`
	Inode     uint64 `json:"inode,omitempty"`
}

// HostPortAnalysis represents the complete port analysis for a host
type HostPortAnalysis struct {
	ScannedAt        time.Time           `json:"scanned_at"`
	Duration         time.Duration       `json:"duration"`
	TotalOpenPorts   int                 `json:"total_open_ports"`
	TCPPorts         []OpenPort          `json:"tcp_ports"`
	UDPPorts         []OpenPort          `json:"udp_ports"`
	ExposedPorts     []OpenPort          `json:"exposed_ports"`     // Ports bound to 0.0.0.0 or ::
	PrivilegedPorts  []OpenPort          `json:"privileged_ports"`  // Ports < 1024
	HighRiskPorts    []HighRiskPort      `json:"high_risk_ports"`   // Known risky services
	UnknownServices  []OpenPort          `json:"unknown_services"`  // Ports without known service
	Recommendations  []string            `json:"recommendations,omitempty"`
	SecurityScore    int                 `json:"security_score"`    // 0-100
}

// HighRiskPort represents a port that is commonly associated with security risks
type HighRiskPort struct {
	OpenPort
	ServiceName string `json:"service_name"`
	Risk        string `json:"risk"`        // low, medium, high, critical
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
}

// Known high-risk ports and their associated services
var knownHighRiskPorts = map[uint16]struct {
	Service     string
	Risk        string
	Description string
	Mitigation  string
}{
	21:    {"FTP", "high", "FTP transmits credentials in plaintext", "Use SFTP or FTPS instead"},
	22:    {"SSH", "medium", "SSH is secure but a common attack target", "Use key-based auth, change default port, use fail2ban"},
	23:    {"Telnet", "critical", "Telnet transmits all data in plaintext", "Disable telnet, use SSH instead"},
	25:    {"SMTP", "medium", "SMTP can be exploited for spam relay", "Ensure proper authentication and relay restrictions"},
	53:    {"DNS", "medium", "DNS can be exploited for amplification attacks", "Configure response rate limiting"},
	69:    {"TFTP", "high", "TFTP has no authentication", "Disable if not needed, restrict access"},
	110:   {"POP3", "high", "POP3 transmits credentials in plaintext", "Use POP3S (port 995) instead"},
	111:   {"RPC", "high", "RPC services can be exploited", "Disable if not needed, use firewall"},
	135:   {"MSRPC", "high", "Windows RPC is a common attack vector", "Block at firewall, disable if possible"},
	137:   {"NetBIOS", "high", "NetBIOS can leak system information", "Disable NetBIOS over TCP/IP"},
	138:   {"NetBIOS", "high", "NetBIOS can be exploited for attacks", "Disable NetBIOS over TCP/IP"},
	139:   {"NetBIOS", "high", "SMB over NetBIOS is insecure", "Use SMB over TCP (port 445) with encryption"},
	143:   {"IMAP", "high", "IMAP transmits credentials in plaintext", "Use IMAPS (port 993) instead"},
	161:   {"SNMP", "high", "SNMP v1/v2 are insecure", "Use SNMP v3 with authentication"},
	162:   {"SNMP-trap", "medium", "SNMP traps may leak information", "Restrict access, use v3"},
	389:   {"LDAP", "medium", "LDAP may transmit credentials in plaintext", "Use LDAPS (port 636) instead"},
	445:   {"SMB", "high", "SMB is frequently targeted by ransomware", "Keep updated, restrict access, disable SMBv1"},
	512:   {"rexec", "critical", "Remote execution service is insecure", "Disable, use SSH instead"},
	513:   {"rlogin", "critical", "Remote login service is insecure", "Disable, use SSH instead"},
	514:   {"rsh/syslog", "high", "Remote shell/syslog may be insecure", "Use SSH for remote access, TLS for syslog"},
	515:   {"LPD", "medium", "Line Printer Daemon may be vulnerable", "Use CUPS with authentication"},
	1433:  {"MSSQL", "high", "Database ports should not be exposed", "Use VPN or tunnel, restrict to localhost"},
	1434:  {"MSSQL-UDP", "high", "SQL Server Browser can leak info", "Disable if not needed"},
	1521:  {"Oracle", "high", "Database ports should not be exposed", "Use VPN or tunnel, restrict to localhost"},
	2049:  {"NFS", "high", "NFS can expose filesystems", "Restrict access, use NFSv4 with Kerberos"},
	2375:  {"Docker", "critical", "Unencrypted Docker API is dangerous", "Use TLS (port 2376), never expose publicly"},
	2376:  {"Docker-TLS", "medium", "Docker API with TLS", "Ensure proper certificate management"},
	3306:  {"MySQL", "high", "Database ports should not be exposed", "Use VPN or tunnel, restrict to localhost"},
	3389:  {"RDP", "high", "RDP is frequently targeted by attackers", "Use VPN, enable NLA, use MFA"},
	5432:  {"PostgreSQL", "high", "Database ports should not be exposed", "Use VPN or tunnel, restrict to localhost"},
	5900:  {"VNC", "high", "VNC may have weak authentication", "Use SSH tunnel, enable strong password"},
	5901:  {"VNC", "high", "VNC may have weak authentication", "Use SSH tunnel, enable strong password"},
	6379:  {"Redis", "critical", "Redis often runs without authentication", "Enable AUTH, bind to localhost, use TLS"},
	8080:  {"HTTP-alt", "low", "Alternative HTTP port", "Ensure proper security headers and TLS"},
	8443:  {"HTTPS-alt", "low", "Alternative HTTPS port", "Verify certificate is valid"},
	9200:  {"Elasticsearch", "high", "Elasticsearch may lack authentication", "Enable security features, restrict access"},
	9300:  {"Elasticsearch", "high", "Elasticsearch cluster port", "Never expose publicly, use firewall"},
	11211: {"Memcached", "critical", "Memcached often lacks authentication", "Bind to localhost, use SASL auth"},
	27017: {"MongoDB", "high", "MongoDB may lack authentication", "Enable authentication, restrict access"},
	27018: {"MongoDB", "high", "MongoDB shard port", "Never expose publicly"},
}

// TCP connection states
const (
	TCP_ESTABLISHED = "01"
	TCP_SYN_SENT    = "02"
	TCP_SYN_RECV    = "03"
	TCP_FIN_WAIT1   = "04"
	TCP_FIN_WAIT2   = "05"
	TCP_TIME_WAIT   = "06"
	TCP_CLOSE       = "07"
	TCP_CLOSE_WAIT  = "08"
	TCP_LAST_ACK    = "09"
	TCP_LISTEN      = "0A"
	TCP_CLOSING     = "0B"
)

var tcpStateNames = map[string]string{
	TCP_ESTABLISHED: "ESTABLISHED",
	TCP_SYN_SENT:    "SYN_SENT",
	TCP_SYN_RECV:    "SYN_RECV",
	TCP_FIN_WAIT1:   "FIN_WAIT1",
	TCP_FIN_WAIT2:   "FIN_WAIT2",
	TCP_TIME_WAIT:   "TIME_WAIT",
	TCP_CLOSE:       "CLOSE",
	TCP_CLOSE_WAIT:  "CLOSE_WAIT",
	TCP_LAST_ACK:    "LAST_ACK",
	TCP_LISTEN:      "LISTEN",
	TCP_CLOSING:     "CLOSING",
}

// ScanHostPorts performs a comprehensive scan of open ports on the host
func (s *HostPortScanner) ScanHostPorts(ctx context.Context) (*HostPortAnalysis, error) {
	log := logger.FromContext(ctx)
	start := time.Now()

	log.Debug("Starting host port scan")

	analysis := &HostPortAnalysis{
		ScannedAt:       time.Now(),
		TCPPorts:        make([]OpenPort, 0),
		UDPPorts:        make([]OpenPort, 0),
		ExposedPorts:    make([]OpenPort, 0),
		PrivilegedPorts: make([]OpenPort, 0),
		HighRiskPorts:   make([]HighRiskPort, 0),
		UnknownServices: make([]OpenPort, 0),
	}

	// Scan TCP ports
	tcpPorts, err := s.scanProcNet("/proc/net/tcp", "tcp")
	if err != nil {
		log.Warn("Failed to scan TCP ports", "error", err)
	} else {
		analysis.TCPPorts = append(analysis.TCPPorts, tcpPorts...)
	}

	// Scan TCP6 ports
	tcp6Ports, err := s.scanProcNet("/proc/net/tcp6", "tcp6")
	if err != nil {
		log.Warn("Failed to scan TCP6 ports", "error", err)
	} else {
		analysis.TCPPorts = append(analysis.TCPPorts, tcp6Ports...)
	}

	// Scan UDP ports
	udpPorts, err := s.scanProcNet("/proc/net/udp", "udp")
	if err != nil {
		log.Warn("Failed to scan UDP ports", "error", err)
	} else {
		analysis.UDPPorts = append(analysis.UDPPorts, udpPorts...)
	}

	// Scan UDP6 ports
	udp6Ports, err := s.scanProcNet("/proc/net/udp6", "udp6")
	if err != nil {
		log.Warn("Failed to scan UDP6 ports", "error", err)
	} else {
		analysis.UDPPorts = append(analysis.UDPPorts, udp6Ports...)
	}

	// Analyze all ports
	allPorts := append(analysis.TCPPorts, analysis.UDPPorts...)
	analysis.TotalOpenPorts = len(allPorts)

	for _, port := range allPorts {
		// Check if exposed (bound to 0.0.0.0 or ::)
		if s.isExposedAddress(port.LocalAddr) {
			analysis.ExposedPorts = append(analysis.ExposedPorts, port)
		}

		// Check if privileged port
		if port.Port < 1024 {
			analysis.PrivilegedPorts = append(analysis.PrivilegedPorts, port)
		}

		// Check if high-risk port
		if riskInfo, exists := knownHighRiskPorts[port.Port]; exists {
			analysis.HighRiskPorts = append(analysis.HighRiskPorts, HighRiskPort{
				OpenPort:    port,
				ServiceName: riskInfo.Service,
				Risk:        riskInfo.Risk,
				Description: riskInfo.Description,
				Mitigation:  riskInfo.Mitigation,
			})
		} else if port.Port > 1024 && !s.isWellKnownPort(port.Port) {
			analysis.UnknownServices = append(analysis.UnknownServices, port)
		}
	}

	// Generate recommendations
	analysis.Recommendations = s.generateRecommendations(analysis)

	// Calculate security score
	analysis.SecurityScore = s.calculateSecurityScore(analysis)

	analysis.Duration = time.Since(start)

	log.Info("Host port scan completed",
		"total_ports", analysis.TotalOpenPorts,
		"exposed", len(analysis.ExposedPorts),
		"high_risk", len(analysis.HighRiskPorts),
		"score", analysis.SecurityScore,
		"duration", analysis.Duration)

	return analysis, nil
}

// scanProcNet reads and parses /proc/net/{tcp,udp,tcp6,udp6} files
func (s *HostPortScanner) scanProcNet(path, protocol string) ([]OpenPort, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer file.Close()

	var ports []OpenPort
	scanner := bufio.NewScanner(file)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		port, err := s.parseProcNetLine(line, protocol)
		if err != nil {
			continue // Skip malformed lines
		}

		// Only include listening ports for TCP, all for UDP
		if strings.HasPrefix(protocol, "tcp") && port.State != "LISTEN" {
			continue
		}

		ports = append(ports, port)
	}

	return ports, scanner.Err()
}

// parseProcNetLine parses a single line from /proc/net/{tcp,udp}
func (s *HostPortScanner) parseProcNetLine(line, protocol string) (OpenPort, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return OpenPort{}, fmt.Errorf("malformed line: not enough fields")
	}

	// Parse local address (field 1)
	localAddr, localPort, err := s.parseHexAddress(fields[1], strings.HasSuffix(protocol, "6"))
	if err != nil {
		return OpenPort{}, err
	}

	// Parse state (field 3 for TCP, not applicable for UDP)
	state := "LISTEN"
	if strings.HasPrefix(protocol, "tcp") {
		if stateName, ok := tcpStateNames[fields[3]]; ok {
			state = stateName
		}
	}

	// Parse UID (field 7)
	uid, _ := strconv.Atoi(fields[7])

	// Parse inode (field 9)
	inode, _ := strconv.ParseUint(fields[9], 10, 64)

	return OpenPort{
		Port:      localPort,
		Protocol:  protocol,
		LocalAddr: localAddr,
		State:     state,
		UID:       uid,
		Inode:     inode,
	}, nil
}

// parseHexAddress parses hex-encoded addresses from /proc/net
func (s *HostPortScanner) parseHexAddress(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format")
	}

	// Parse port (always 4 hex chars)
	portNum, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}

	// Parse IP address
	var ip net.IP
	if isIPv6 {
		// IPv6 addresses are 32 hex chars
		if len(parts[0]) != 32 {
			return "", 0, fmt.Errorf("invalid IPv6 address length")
		}
		ipBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			return "", 0, err
		}
		// Reverse byte order for each 4-byte group (little-endian to big-endian)
		for i := 0; i < 4; i++ {
			start := i * 4
			ipBytes[start], ipBytes[start+1], ipBytes[start+2], ipBytes[start+3] =
				ipBytes[start+3], ipBytes[start+2], ipBytes[start+1], ipBytes[start]
		}
		ip = net.IP(ipBytes)
	} else {
		// IPv4 addresses are 8 hex chars
		if len(parts[0]) != 8 {
			return "", 0, fmt.Errorf("invalid IPv4 address length")
		}
		ipBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			return "", 0, err
		}
		// Reverse byte order (little-endian to big-endian)
		ip = net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
	}

	return ip.String(), uint16(portNum), nil
}

// isExposedAddress checks if an address is exposed (0.0.0.0 or ::)
func (s *HostPortScanner) isExposedAddress(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "::ffff:0.0.0.0"
}

// isWellKnownPort checks if a port is a well-known service port
func (s *HostPortScanner) isWellKnownPort(port uint16) bool {
	wellKnownPorts := map[uint16]bool{
		80: true, 443: true, 8000: true, 8080: true, 8443: true, 9000: true,
		// Add more well-known application ports
	}
	_, exists := knownHighRiskPorts[port]
	return exists || wellKnownPorts[port]
}

// generateRecommendations generates security recommendations based on the analysis
func (s *HostPortScanner) generateRecommendations(analysis *HostPortAnalysis) []string {
	var recommendations []string

	// Check for critical/high risk exposed ports
	for _, hrp := range analysis.HighRiskPorts {
		if hrp.Risk == "critical" || hrp.Risk == "high" {
			if s.isExposedAddress(hrp.LocalAddr) {
				recommendations = append(recommendations,
					fmt.Sprintf("CRITICAL: Port %d (%s) is exposed to all interfaces. %s",
						hrp.Port, hrp.ServiceName, hrp.Mitigation))
			}
		}
	}

	// Check for exposed privileged ports
	exposedPrivileged := 0
	for _, port := range analysis.PrivilegedPorts {
		if s.isExposedAddress(port.LocalAddr) {
			exposedPrivileged++
		}
	}
	if exposedPrivileged > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Found %d privileged port(s) exposed to all interfaces. Consider binding to localhost or specific IP.",
				exposedPrivileged))
	}

	// Check for too many exposed ports
	if len(analysis.ExposedPorts) > 10 {
		recommendations = append(recommendations,
			fmt.Sprintf("High number of exposed ports (%d). Review if all services need to be accessible externally.",
				len(analysis.ExposedPorts)))
	}

	// Check for unknown services
	if len(analysis.UnknownServices) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Found %d port(s) running unknown services. Verify these are legitimate applications.",
				len(analysis.UnknownServices)))
	}

	// General recommendations if no specific issues
	if len(recommendations) == 0 {
		recommendations = append(recommendations,
			"No critical port security issues detected. Continue monitoring for changes.")
	}

	return recommendations
}

// calculateSecurityScore calculates a security score based on port analysis
func (s *HostPortScanner) calculateSecurityScore(analysis *HostPortAnalysis) int {
	score := 100

	// Deduct for critical risk ports exposed
	for _, hrp := range analysis.HighRiskPorts {
		if s.isExposedAddress(hrp.LocalAddr) {
			switch hrp.Risk {
			case "critical":
				score -= 20
			case "high":
				score -= 10
			case "medium":
				score -= 5
			case "low":
				score -= 2
			}
		}
	}

	// Deduct for exposed privileged ports
	for _, port := range analysis.PrivilegedPorts {
		if s.isExposedAddress(port.LocalAddr) {
			score -= 3
		}
	}

	// Deduct for too many exposed ports
	exposedCount := len(analysis.ExposedPorts)
	if exposedCount > 20 {
		score -= 15
	} else if exposedCount > 10 {
		score -= 10
	} else if exposedCount > 5 {
		score -= 5
	}

	// Deduct for unknown services
	score -= len(analysis.UnknownServices)

	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// GetProcessForPort attempts to find the process using a given port
// This requires reading /proc/<pid>/fd symlinks which needs root privileges
func (s *HostPortScanner) GetProcessForPort(inode uint64) (int, string, error) {
	// Walk /proc looking for the process with this inode
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", err
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		// Check if directory name is a number (PID)
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		// Read fd directory
		fdPath := filepath.Join("/proc", proc.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue // May not have permission
		}

		for _, fd := range fds {
			linkPath := filepath.Join(fdPath, fd.Name())
			link, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Check if this fd points to our socket
			expectedSocket := fmt.Sprintf("socket:[%d]", inode)
			if link == expectedSocket {
				// Found it! Get process name
				commPath := filepath.Join("/proc", proc.Name(), "comm")
				comm, err := os.ReadFile(commPath)
				if err != nil {
					return pid, "", nil
				}
				return pid, strings.TrimSpace(string(comm)), nil
			}
		}
	}

	return 0, "", fmt.Errorf("process not found for inode %d", inode)
}

// EnrichWithProcessInfo adds process information to open ports
func (s *HostPortScanner) EnrichWithProcessInfo(ports []OpenPort) {
	for i := range ports {
		if ports[i].Inode > 0 {
			pid, proc, err := s.GetProcessForPort(ports[i].Inode)
			if err == nil {
				ports[i].PID = pid
				ports[i].Process = proc
			}
		}
	}
}
