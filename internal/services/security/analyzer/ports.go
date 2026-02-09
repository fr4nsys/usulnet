// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"fmt"
	"strconv"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// PortsAnalyzer checks for port exposure security issues
type PortsAnalyzer struct {
	security.BaseAnalyzer
}

// NewPortsAnalyzer creates a new ports analyzer
func NewPortsAnalyzer() *PortsAnalyzer {
	return &PortsAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"ports",
			"Checks for dangerous port exposure and public binding",
		),
	}
}

// Analyze checks the container for port-related security issues
func (a *PortsAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get check definitions
	checks := models.DefaultSecurityChecks()
	var portExposureCheck, portDangerousCheck models.SecurityCheck
	for _, c := range checks {
		switch c.ID {
		case models.CheckPortExposure:
			portExposureCheck = c
		case models.CheckPortDangerous:
			portDangerousCheck = c
		}
	}

	publicExposedPorts := 0
	var dangerousPorts []uint16
	var publicBindPorts []portInfo

	for _, port := range data.Ports {
		if port.HostPort == 0 {
			continue // Not exposed to host
		}

		// Check if bound to all interfaces (0.0.0.0 or empty)
		isPublic := port.HostIP == "" || port.HostIP == "0.0.0.0" || port.HostIP == "::"

		if isPublic {
			publicExposedPorts++
			publicBindPorts = append(publicBindPorts, portInfo{
				ContainerPort: port.ContainerPort,
				HostPort:      port.HostPort,
				HostIP:        port.HostIP,
				Protocol:      port.Protocol,
			})
		}

		// Check for dangerous ports
		if _, isDangerous := security.DangerousPorts[port.ContainerPort]; isDangerous {
			dangerousPorts = append(dangerousPorts, port.ContainerPort)
		}
		if port.ContainerPort != port.HostPort {
			if _, isDangerous := security.DangerousPorts[port.HostPort]; isDangerous {
				dangerousPorts = append(dangerousPorts, port.HostPort)
			}
		}
	}

	// Report public exposure
	if publicExposedPorts > 0 {
		description := fmt.Sprintf(
			"Container has %d port(s) bound to 0.0.0.0 (all interfaces), "+
				"making them accessible from any network. This may expose "+
				"services to the internet if not protected by a firewall.",
			publicExposedPorts,
		)

		issue := security.NewIssue(portExposureCheck, description).
			WithDetail("container", data.Name).
			WithDetail("public_ports_count", publicExposedPorts)

		// Add port details
		portDetails := make([]string, 0, len(publicBindPorts))
		for _, p := range publicBindPorts {
			detail := fmt.Sprintf("%d->%d/%s", p.HostPort, p.ContainerPort, p.Protocol)
			portDetails = append(portDetails, detail)
		}
		issue = issue.WithDetail("ports", portDetails)

		// Adjust penalty based on count
		if publicExposedPorts > 5 {
			issue.Penalty = portExposureCheck.ScoreImpact * 2
		} else {
			issue.Penalty = portExposureCheck.ScoreImpact * publicExposedPorts
		}

		issues = append(issues, issue)
	}

	// Report dangerous ports
	if len(dangerousPorts) > 0 {
		// Deduplicate
		uniquePorts := make(map[uint16]bool)
		for _, p := range dangerousPorts {
			uniquePorts[p] = true
		}

		portNames := make([]string, 0, len(uniquePorts))
		for p := range uniquePorts {
			name := security.DangerousPorts[p]
			portNames = append(portNames, fmt.Sprintf("%d (%s)", p, name))
		}

		description := fmt.Sprintf(
			"Container exposes commonly attacked ports: %v. "+
				"These services are frequent targets for automated attacks.",
			portNames,
		)

		issue := security.NewIssue(portDangerousCheck, description).
			WithDetail("container", data.Name).
			WithDetail("dangerous_ports", portNames)

		// Adjust penalty based on count
		issue.Penalty = portDangerousCheck.ScoreImpact * len(uniquePorts)
		if issue.Penalty > 30 {
			issue.Penalty = 30 // Cap at 30
		}

		issues = append(issues, issue)
	}

	return issues, nil
}

// portInfo holds information about an exposed port
type portInfo struct {
	ContainerPort uint16
	HostPort      uint16
	HostIP        string
	Protocol      string
}

// String returns a string representation of the port info
func (p portInfo) String() string {
	hostIP := p.HostIP
	if hostIP == "" {
		hostIP = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d->%d/%s", hostIP, p.HostPort, p.ContainerPort, p.Protocol)
}

// ParsePortString parses a port string like "8080/tcp" into port number and protocol
func ParsePortString(portStr string) (uint16, string) {
	// Handle formats like "8080/tcp", "8080", "443/tcp"
	port := portStr
	protocol := "tcp"

	if idx := len(portStr) - 4; idx > 0 && (portStr[idx:] == "/tcp" || portStr[idx:] == "/udp") {
		port = portStr[:idx]
		protocol = portStr[idx+1:]
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, protocol
	}

	return uint16(portNum), protocol
}
