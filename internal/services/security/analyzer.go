// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package security provides container security analysis, scoring, and CVE scanning.
// It analyzes containers for security best practices and vulnerabilities,
// generating actionable recommendations for remediation.
package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Analyzer defines the interface for security analyzers.
// Each analyzer checks for a specific category of security issues.
type Analyzer interface {
	// Name returns the analyzer's unique identifier
	Name() string

	// Description returns a human-readable description
	Description() string

	// Analyze inspects a container and returns any security issues found
	Analyze(ctx context.Context, data *ContainerData) ([]Issue, error)

	// IsEnabled returns whether this analyzer is currently enabled
	IsEnabled() bool

	// SetEnabled enables or disables the analyzer
	SetEnabled(enabled bool)
}

// ContainerData holds all the information needed for security analysis.
// It's a normalized structure that abstracts the Docker API response.
type ContainerData struct {
	// Basic identification
	ID    string
	Name  string
	Image string

	// Container configuration
	User         string            // User running in container
	Env          []string          // Environment variables
	Labels       map[string]string // Container labels
	Cmd          []string          // Command
	Entrypoint   []string          // Entrypoint
	WorkingDir   string            // Working directory
	Healthcheck  *HealthcheckData  // Healthcheck configuration

	// Host configuration
	Privileged     bool              // Privileged mode
	ReadonlyRootfs bool              // Read-only filesystem
	NetworkMode    string            // Network mode (bridge, host, etc.)
	PidMode        string            // PID namespace mode
	IpcMode        string            // IPC namespace mode
	CapAdd         []string          // Added capabilities
	CapDrop        []string          // Dropped capabilities
	SecurityOpt    []string          // Security options
	RestartPolicy  string            // Restart policy name

	// Resource limits
	MemoryLimit   int64 // Memory limit in bytes
	MemorySwap    int64 // Memory+Swap limit
	CPUShares     int64 // CPU shares
	CPUQuota      int64 // CPU quota
	CPUPeriod     int64 // CPU period
	NanoCPUs      int64 // CPU limit in nano CPUs
	PidsLimit     int64 // PIDs limit

	// Networking
	Ports    []PortData    // Port mappings
	Networks []NetworkData // Network attachments

	// Storage
	Mounts []MountData // Volume mounts
	Binds  []string    // Bind mounts

	// State
	Running bool
	Health  string // healthy, unhealthy, starting, none
}

// HealthcheckData represents healthcheck configuration
type HealthcheckData struct {
	Test        []string // Health check command
	Interval    int64    // Interval in nanoseconds
	Timeout     int64    // Timeout in nanoseconds
	Retries     int      // Number of retries
	StartPeriod int64    // Start period in nanoseconds
}

// PortData represents a port mapping
type PortData struct {
	ContainerPort uint16
	HostPort      uint16
	HostIP        string
	Protocol      string // tcp, udp
}

// NetworkData represents network attachment information
type NetworkData struct {
	Name      string
	NetworkID string
	IPAddress string
	Gateway   string
}

// MountData represents a mount point
type MountData struct {
	Type        string // bind, volume, tmpfs
	Source      string
	Destination string
	Mode        string // rw, ro
	RW          bool
	Propagation string
}

// Issue represents a security issue found during analysis
type Issue struct {
	CheckID        string              // Unique check identifier (e.g., "USER_001")
	Severity       models.IssueSeverity
	Category       models.IssueCategory
	Title          string
	Description    string
	Recommendation string
	FixCommand     string // Command to fix the issue
	DocURL         string // Documentation URL
	Penalty        int    // Score penalty
	Details        map[string]interface{} // Additional context
}

// NewIssue creates a new Issue from a SecurityCheck definition
func NewIssue(check models.SecurityCheck, description string) Issue {
	return Issue{
		CheckID:        check.ID,
		Severity:       check.Severity,
		Category:       check.Category,
		Title:          check.Name,
		Description:    description,
		Recommendation: check.Description,
		FixCommand:     check.FixCommand,
		DocURL:         check.DocURL,
		Penalty:        check.ScoreImpact,
	}
}

// WithDetails adds details to an issue
func (i Issue) WithDetails(details map[string]interface{}) Issue {
	i.Details = details
	return i
}

// WithDetail adds a single detail to an issue
func (i Issue) WithDetail(key string, value interface{}) Issue {
	if i.Details == nil {
		i.Details = make(map[string]interface{})
	}
	i.Details[key] = value
	return i
}

// ContainerDataFromInspect converts Docker API inspect response to ContainerData
func ContainerDataFromInspect(inspect types.ContainerJSON) *ContainerData {
	data := &ContainerData{
		ID:    inspect.ID,
		Name:  strings.TrimPrefix(inspect.Name, "/"),
		Image: inspect.Config.Image,
	}

	// Configuration
	if inspect.Config != nil {
		data.User = inspect.Config.User
		data.Env = inspect.Config.Env
		data.Labels = inspect.Config.Labels
		data.Cmd = inspect.Config.Cmd
		data.Entrypoint = inspect.Config.Entrypoint
		data.WorkingDir = inspect.Config.WorkingDir

		if inspect.Config.Healthcheck != nil {
			data.Healthcheck = &HealthcheckData{
				Test:        inspect.Config.Healthcheck.Test,
				Interval:    int64(inspect.Config.Healthcheck.Interval),
				Timeout:     int64(inspect.Config.Healthcheck.Timeout),
				Retries:     inspect.Config.Healthcheck.Retries,
				StartPeriod: int64(inspect.Config.Healthcheck.StartPeriod),
			}
		}
	}

	// Host configuration
	if inspect.HostConfig != nil {
		data.Privileged = inspect.HostConfig.Privileged
		data.ReadonlyRootfs = inspect.HostConfig.ReadonlyRootfs
		data.NetworkMode = string(inspect.HostConfig.NetworkMode)
		data.PidMode = string(inspect.HostConfig.PidMode)
		data.IpcMode = string(inspect.HostConfig.IpcMode)
		data.CapAdd = inspect.HostConfig.CapAdd
		data.CapDrop = inspect.HostConfig.CapDrop
		data.SecurityOpt = inspect.HostConfig.SecurityOpt
		data.Binds = inspect.HostConfig.Binds

		if inspect.HostConfig.RestartPolicy.Name != "" {
			data.RestartPolicy = string(inspect.HostConfig.RestartPolicy.Name)
		}

		// Resources
		data.MemoryLimit = inspect.HostConfig.Memory
		data.MemorySwap = inspect.HostConfig.MemorySwap
		data.CPUShares = inspect.HostConfig.CPUShares
		data.CPUQuota = inspect.HostConfig.CPUQuota
		data.CPUPeriod = inspect.HostConfig.CPUPeriod
		data.NanoCPUs = inspect.HostConfig.NanoCPUs

		if inspect.HostConfig.PidsLimit != nil {
			data.PidsLimit = *inspect.HostConfig.PidsLimit
		}
	}

	// Port bindings from NetworkSettings
	if inspect.NetworkSettings != nil {
		for port, bindings := range inspect.NetworkSettings.Ports {
			for _, binding := range bindings {
				hostPort := uint16(0)
				if binding.HostPort != "" {
					// Parse port - ignore errors, will be 0
					var hp int
					fmt.Sscanf(binding.HostPort, "%d", &hp)
					hostPort = uint16(hp)
				}

				data.Ports = append(data.Ports, PortData{
					ContainerPort: uint16(port.Int()),
					HostPort:      hostPort,
					HostIP:        binding.HostIP,
					Protocol:      port.Proto(),
				})
			}
		}

		// Networks
		for name, settings := range inspect.NetworkSettings.Networks {
			if settings != nil {
				data.Networks = append(data.Networks, NetworkData{
					Name:      name,
					NetworkID: settings.NetworkID,
					IPAddress: settings.IPAddress,
					Gateway:   settings.Gateway,
				})
			}
		}
	}

	// Mounts
	for _, mount := range inspect.Mounts {
		mode := "rw"
		if !mount.RW {
			mode = "ro"
		}
		data.Mounts = append(data.Mounts, MountData{
			Type:        string(mount.Type),
			Source:      mount.Source,
			Destination: mount.Destination,
			Mode:        mode,
			RW:          mount.RW,
			Propagation: string(mount.Propagation),
		})
	}

	// State
	if inspect.State != nil {
		data.Running = inspect.State.Running
		if inspect.State.Health != nil {
			data.Health = inspect.State.Health.Status
		}
	}

	return data
}

// BaseAnalyzer provides common functionality for analyzers
type BaseAnalyzer struct {
	name        string
	description string
	enabled     bool
}

// Name returns the analyzer name
func (a *BaseAnalyzer) Name() string {
	return a.name
}

// Description returns the analyzer description
func (a *BaseAnalyzer) Description() string {
	return a.description
}

// IsEnabled returns whether the analyzer is enabled
func (a *BaseAnalyzer) IsEnabled() bool {
	return a.enabled
}

// SetEnabled sets the analyzer enabled state
func (a *BaseAnalyzer) SetEnabled(enabled bool) {
	a.enabled = enabled
}

// NewBaseAnalyzer creates a new BaseAnalyzer
func NewBaseAnalyzer(name, description string) BaseAnalyzer {
	return BaseAnalyzer{
		name:        name,
		description: description,
		enabled:     true,
	}
}

// DangerousPorts is a list of commonly attacked ports
var DangerousPorts = map[uint16]string{
	22:    "SSH",
	23:    "Telnet",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	11211: "Memcached",
	2375:  "Docker (unencrypted)",
	2376:  "Docker (TLS)",
	5672:  "RabbitMQ",
	15672: "RabbitMQ Management",
	8500:  "Consul",
	2181:  "ZooKeeper",
	9092:  "Kafka",
}

// SecretPatterns contains patterns that may indicate secrets in environment variables
var SecretPatterns = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"api-key",
	"private_key",
	"privatekey",
	"private-key",
	"access_key",
	"accesskey",
	"access-key",
	"secret_key",
	"secretkey",
	"secret-key",
	"auth_token",
	"authtoken",
	"auth-token",
	"bearer",
	"credential",
	"cert",
	"private",
}

// DangerousCapabilities lists capabilities that significantly increase risk
var DangerousCapabilities = []string{
	"SYS_ADMIN",
	"NET_ADMIN",
	"SYS_PTRACE",
	"SYS_MODULE",
	"DAC_READ_SEARCH",
	"DAC_OVERRIDE",
	"SETUID",
	"SETGID",
	"SYS_RAWIO",
	"SYS_CHROOT",
	"MKNOD",
	"AUDIT_CONTROL",
	"AUDIT_WRITE",
	"BLOCK_SUSPEND",
	"MAC_ADMIN",
	"MAC_OVERRIDE",
	"NET_RAW",
	"SYS_BOOT",
	"SYS_TIME",
	"WAKE_ALARM",
}
