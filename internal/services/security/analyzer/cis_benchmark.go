// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// CISBenchmarkAnalyzer performs security checks based on CIS Docker Benchmark v1.6.0
// https://www.cisecurity.org/benchmark/docker
type CISBenchmarkAnalyzer struct {
	security.BaseAnalyzer

	// Configuration options
	StrictMode bool // Enable stricter checks
}

// NewCISBenchmarkAnalyzer creates a new CIS Docker Benchmark analyzer
func NewCISBenchmarkAnalyzer() *CISBenchmarkAnalyzer {
	return &CISBenchmarkAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"cis-benchmark",
			"CIS Docker Benchmark v1.6.0 container runtime security checks",
		),
		StrictMode: false,
	}
}

// NewCISBenchmarkAnalyzerStrict creates a CIS analyzer with strict mode enabled
func NewCISBenchmarkAnalyzerStrict() *CISBenchmarkAnalyzer {
	a := NewCISBenchmarkAnalyzer()
	a.StrictMode = true
	return a
}

// CIS Check IDs follow CIS Docker Benchmark numbering
const (
	// Section 4: Container Images and Build File Configuration
	CISCheckContainerUser   = "CIS-4.1" // Ensure a user for the container has been created
	CISCheckContentTrust    = "CIS-4.5" // Ensure Content trust for Docker is enabled
	CISCheckHealthcheck     = "CIS-4.6" // Ensure HEALTHCHECK instructions have been added to container images

	// Section 5: Container Runtime Configuration
	CISCheckAppArmorProfile   = "CIS-5.1"  // Ensure that, if applicable, an AppArmor Profile is enabled
	CISCheckSELinuxOptions    = "CIS-5.2"  // Ensure that, if applicable, SELinux security options are set
	CISCheckCapabilities      = "CIS-5.3"  // Ensure that Linux kernel capabilities are restricted
	CISCheckPrivileged        = "CIS-5.4"  // Ensure that privileged containers are not used
	CISCheckSensitiveHostDirs = "CIS-5.5"  // Ensure sensitive host system directories are not mounted
	CISCheckSSHInContainer    = "CIS-5.6"  // Ensure sshd is not run within containers
	CISCheckPrivilegedPorts   = "CIS-5.7"  // Ensure privileged ports are not mapped
	CISCheckOpenPorts         = "CIS-5.8"  // Ensure that only needed ports are open on the container
	CISCheckHostNetworkMode   = "CIS-5.9"  // Ensure that the host's network namespace is not shared
	CISCheckMemoryLimit       = "CIS-5.10" // Ensure memory usage for containers is limited
	CISCheckCPUPriority       = "CIS-5.11" // Ensure that CPU priority is set appropriately
	CISCheckReadOnlyRootFS    = "CIS-5.12" // Ensure that the container's root filesystem is mounted as read only
	CISCheckBindHostInterface = "CIS-5.13" // Ensure that incoming container traffic is bound to specific host interface
	CISCheckRestartPolicy     = "CIS-5.14" // Ensure that the 'on-failure' restart policy is set to '5'
	CISCheckHostPIDNamespace  = "CIS-5.15" // Ensure that the host's process namespace is not shared
	CISCheckHostIPCNamespace  = "CIS-5.16" // Ensure that the host's IPC namespace is not shared
	CISCheckHostDevices       = "CIS-5.17" // Ensure that host devices are not directly exposed to containers
	CISCheckDefaultUlimit     = "CIS-5.18" // Ensure that the default ulimit is overwritten at runtime if needed
	CISCheckMountPropagation  = "CIS-5.19" // Ensure mount propagation mode is not set to shared
	CISCheckHostUTSNamespace  = "CIS-5.20" // Ensure that the host's UTS namespace is not shared
	CISCheckSeccompDefault    = "CIS-5.21" // Ensure the default seccomp profile is not Disabled
	CISCheckDockerExec        = "CIS-5.22" // Ensure that docker exec commands are not used with privileged option
	CISCheckCgroupConfirm     = "CIS-5.24" // Ensure that cgroup usage is confirmed
	CISCheckNoNewPrivileges   = "CIS-5.25" // Ensure that the container is restricted from acquiring additional privileges
	CISCheckHealthcheckRT     = "CIS-5.26" // Ensure that container health is checked at runtime
	CISCheckDockerCommands    = "CIS-5.27" // Ensure that Docker commands always make use of the latest version
	CISCheckPIDCgroup         = "CIS-5.28" // Ensure that the PIDs cgroup limit is used
	CISCheckBridgeNetwork     = "CIS-5.29" // Ensure that Docker's default bridge docker0 is not used
	CISCheckUserNamespace     = "CIS-5.30" // Ensure that the host's user namespaces are not shared
	CISCheckDockerSocket      = "CIS-5.31" // Ensure that the Docker socket is not mounted inside containers
)

// CISCheck represents a CIS Docker Benchmark check with metadata
type CISCheck struct {
	ID             string
	Section        string
	Title          string
	Description    string
	Recommendation string
	Severity       models.IssueSeverity
	Category       models.IssueCategory
	Penalty        int
	DocURL         string
}

// Analyze performs CIS Docker Benchmark checks on a container
func (a *CISBenchmarkAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Section 4: Container Images and Build File
	issues = append(issues, a.checkContainerUser(data)...)
	issues = append(issues, a.checkHealthcheck(data)...)

	// Section 5: Container Runtime Configuration
	issues = append(issues, a.checkAppArmorProfile(data)...)
	issues = append(issues, a.checkSELinuxOptions(data)...)
	issues = append(issues, a.checkCapabilities(data)...)
	issues = append(issues, a.checkPrivilegedMode(data)...)
	issues = append(issues, a.checkSensitiveHostDirs(data)...)
	issues = append(issues, a.checkPrivilegedPorts(data)...)
	issues = append(issues, a.checkHostNetworkMode(data)...)
	issues = append(issues, a.checkMemoryLimit(data)...)
	issues = append(issues, a.checkCPUPriority(data)...)
	issues = append(issues, a.checkReadOnlyRootFS(data)...)
	issues = append(issues, a.checkBindHostInterface(data)...)
	issues = append(issues, a.checkRestartPolicy(data)...)
	issues = append(issues, a.checkHostPIDNamespace(data)...)
	issues = append(issues, a.checkHostIPCNamespace(data)...)
	issues = append(issues, a.checkHostDevices(data)...)
	issues = append(issues, a.checkMountPropagation(data)...)
	issues = append(issues, a.checkSeccompProfile(data)...)
	issues = append(issues, a.checkNoNewPrivileges(data)...)
	issues = append(issues, a.checkPIDsLimit(data)...)
	issues = append(issues, a.checkDefaultBridgeNetwork(data)...)
	issues = append(issues, a.checkDockerSocket(data)...)

	return issues, nil
}

// checkContainerUser checks CIS 4.1: Ensure a user for the container has been created
func (a *CISBenchmarkAnalyzer) checkContainerUser(data *security.ContainerData) []security.Issue {
	if isRootUser(data.User) {
		issue := security.Issue{
			CheckID:  CISCheckContainerUser,
			Severity: models.IssueSeverityHigh,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 4.1: Container Running as Root",
			Description: fmt.Sprintf("Container '%s' is running as root user. "+
				"Running containers as root defeats the purpose of user namespace isolation "+
				"and increases the attack surface.", data.Name),
			Recommendation: "Create a non-root user in the Dockerfile and use the USER instruction, " +
				"or run with --user flag specifying a non-root user.",
			FixCommand: fmt.Sprintf("docker run --user 1000:1000 %s", data.Image),
			DocURL:     "https://www.cisecurity.org/benchmark/docker",
			Penalty:    15,
		}
		return []security.Issue{issue.WithDetail("current_user", normalizeUserDisplay(data.User)).WithDetail("container", data.Name)}
	}
	return nil
}

// checkHealthcheck checks CIS 4.6: Ensure HEALTHCHECK instructions have been added
func (a *CISBenchmarkAnalyzer) checkHealthcheck(data *security.ContainerData) []security.Issue {
	if data.Healthcheck == nil || len(data.Healthcheck.Test) == 0 {
		issue := security.Issue{
			CheckID:  CISCheckHealthcheck,
			Severity: models.IssueSeverityLow,
			Category: models.IssueCategoryReliability,
			Title:    "CIS 4.6: No Health Check Configured",
			Description: fmt.Sprintf("Container '%s' does not have a health check configured. "+
				"Health checks ensure containers are functioning properly and enable automatic recovery.", data.Name),
			Recommendation: "Add a HEALTHCHECK instruction to the Dockerfile or specify --health-cmd at runtime.",
			FixCommand:     "docker run --health-cmd='curl -f http://localhost/ || exit 1' --health-interval=30s " + data.Image,
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        3,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkAppArmorProfile checks CIS 5.1: Ensure AppArmor Profile is enabled
func (a *CISBenchmarkAnalyzer) checkAppArmorProfile(data *security.ContainerData) []security.Issue {
	for _, opt := range data.SecurityOpt {
		if strings.HasPrefix(strings.ToLower(opt), "apparmor=unconfined") {
			issue := security.Issue{
				CheckID:  CISCheckAppArmorProfile,
				Severity: models.IssueSeverityHigh,
				Category: models.IssueCategorySecurity,
				Title:    "CIS 5.1: AppArmor Profile Disabled",
				Description: fmt.Sprintf("Container '%s' has AppArmor set to unconfined, "+
					"disabling mandatory access control protection.", data.Name),
				Recommendation: "Remove the apparmor=unconfined option or specify a valid AppArmor profile.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        12,
			}
			return []security.Issue{issue.WithDetail("security_opt", opt).WithDetail("container", data.Name)}
		}
	}
	return nil
}

// checkSELinuxOptions checks CIS 5.2: Ensure SELinux security options are set
func (a *CISBenchmarkAnalyzer) checkSELinuxOptions(data *security.ContainerData) []security.Issue {
	for _, opt := range data.SecurityOpt {
		if strings.HasPrefix(strings.ToLower(opt), "label=disable") ||
			strings.HasPrefix(strings.ToLower(opt), "label:disable") {
			issue := security.Issue{
				CheckID:  CISCheckSELinuxOptions,
				Severity: models.IssueSeverityMedium,
				Category: models.IssueCategorySecurity,
				Title:    "CIS 5.2: SELinux Labeling Disabled",
				Description: fmt.Sprintf("Container '%s' has SELinux labeling disabled, "+
					"reducing security isolation.", data.Name),
				Recommendation: "Enable SELinux labeling by removing the label=disable option.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        8,
			}
			return []security.Issue{issue.WithDetail("security_opt", opt).WithDetail("container", data.Name)}
		}
	}
	return nil
}

// checkCapabilities checks CIS 5.3: Ensure Linux kernel capabilities are restricted
func (a *CISBenchmarkAnalyzer) checkCapabilities(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	// Check for dangerous capabilities
	dangerousCaps := map[string]string{
		"SYS_ADMIN":       "Allows nearly all administrative operations",
		"NET_ADMIN":       "Allows network configuration changes",
		"SYS_PTRACE":      "Allows process tracing and debugging",
		"SYS_MODULE":      "Allows loading/unloading kernel modules",
		"DAC_READ_SEARCH": "Bypasses file read permission checks",
		"SYS_RAWIO":       "Allows raw I/O port access",
		"SYS_BOOT":        "Allows rebooting the system",
		"SYS_TIME":        "Allows changing system time",
		"MAC_ADMIN":       "Allows MAC configuration changes",
		"MAC_OVERRIDE":    "Allows MAC policy override",
	}

	for _, cap := range data.CapAdd {
		cap = strings.ToUpper(strings.TrimPrefix(cap, "CAP_"))
		if desc, dangerous := dangerousCaps[cap]; dangerous {
			issue := security.Issue{
				CheckID:  CISCheckCapabilities,
				Severity: models.IssueSeverityHigh,
				Category: models.IssueCategorySecurity,
				Title:    fmt.Sprintf("CIS 5.3: Dangerous Capability %s Added", cap),
				Description: fmt.Sprintf("Container '%s' has dangerous capability %s. %s. "+
					"This significantly increases the container's attack surface.", data.Name, cap, desc),
				Recommendation: fmt.Sprintf("Remove the %s capability unless absolutely required. "+
					"Consider if the functionality can be achieved with more limited capabilities.", cap),
				DocURL:  "https://www.cisecurity.org/benchmark/docker",
				Penalty: 15,
			}
			issues = append(issues, issue.WithDetail("capability", cap).WithDetail("container", data.Name))
		}
	}

	return issues
}

// checkPrivilegedMode checks CIS 5.4: Ensure privileged containers are not used
func (a *CISBenchmarkAnalyzer) checkPrivilegedMode(data *security.ContainerData) []security.Issue {
	if data.Privileged {
		issue := security.Issue{
			CheckID:  CISCheckPrivileged,
			Severity: models.IssueSeverityCritical,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.4: Privileged Mode Enabled",
			Description: fmt.Sprintf("Container '%s' is running in privileged mode. "+
				"This grants the container almost all capabilities of the host, "+
				"effectively disabling container isolation. An attacker with container "+
				"access can trivially escape to the host system.", data.Name),
			Recommendation: "Remove the --privileged flag. If elevated access is needed, " +
				"use specific capabilities (--cap-add) for only what's required.",
			DocURL:  "https://www.cisecurity.org/benchmark/docker",
			Penalty: 30,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkSensitiveHostDirs checks CIS 5.5: Ensure sensitive host system directories are not mounted
func (a *CISBenchmarkAnalyzer) checkSensitiveHostDirs(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	sensitivePaths := map[string]string{
		"/":                "Root filesystem",
		"/boot":            "Boot partition",
		"/dev":             "Device files",
		"/etc":             "System configuration",
		"/lib":             "System libraries",
		"/proc":            "Process information",
		"/sys":             "Kernel/system information",
		"/usr":             "User programs",
		"/var/run":         "Runtime data",
		"/run":             "Runtime data",
		"/var/log":         "System logs",
		"/etc/passwd":      "User accounts",
		"/etc/shadow":      "Password hashes",
		"/etc/hosts":       "Host file",
		"/etc/resolv.conf": "DNS configuration",
	}

	for _, mount := range data.Mounts {
		if mount.Type != "bind" {
			continue
		}

		for sensitivePath, description := range sensitivePaths {
			if mount.Source == sensitivePath || strings.HasPrefix(mount.Source, sensitivePath+"/") {
				severity := models.IssueSeverityHigh
				if sensitivePath == "/" || sensitivePath == "/etc" || sensitivePath == "/proc" || sensitivePath == "/sys" {
					severity = models.IssueSeverityCritical
				}

				issue := security.Issue{
					CheckID:  CISCheckSensitiveHostDirs,
					Severity: severity,
					Category: models.IssueCategorySecurity,
					Title:    fmt.Sprintf("CIS 5.5: Sensitive Host Path Mounted (%s)", sensitivePath),
					Description: fmt.Sprintf("Container '%s' has sensitive host directory '%s' (%s) "+
						"mounted at '%s'. This could allow container escape or data exfiltration.",
						data.Name, mount.Source, description, mount.Destination),
					Recommendation: "Remove the bind mount for sensitive host directories. " +
						"Use volumes or secrets management instead.",
					DocURL:  "https://www.cisecurity.org/benchmark/docker",
					Penalty: 20,
				}
				issues = append(issues, issue.WithDetail("source", mount.Source).WithDetail("destination", mount.Destination).WithDetail("container", data.Name))
				break
			}
		}
	}

	// Also check Binds
	for _, bind := range data.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) < 2 {
			continue
		}
		source := parts[0]

		for sensitivePath, description := range sensitivePaths {
			if source == sensitivePath || strings.HasPrefix(source, sensitivePath+"/") {
				severity := models.IssueSeverityHigh
				if sensitivePath == "/" || sensitivePath == "/etc" || sensitivePath == "/proc" || sensitivePath == "/sys" {
					severity = models.IssueSeverityCritical
				}

				issue := security.Issue{
					CheckID:  CISCheckSensitiveHostDirs,
					Severity: severity,
					Category: models.IssueCategorySecurity,
					Title:    fmt.Sprintf("CIS 5.5: Sensitive Host Path Mounted (%s)", sensitivePath),
					Description: fmt.Sprintf("Container '%s' has sensitive host directory '%s' (%s) bound. "+
						"This could allow container escape or data exfiltration.",
						data.Name, source, description),
					Recommendation: "Remove the bind mount for sensitive host directories.",
					DocURL:         "https://www.cisecurity.org/benchmark/docker",
					Penalty:        20,
				}
				issues = append(issues, issue.WithDetail("bind", bind).WithDetail("container", data.Name))
				break
			}
		}
	}

	return issues
}

// checkPrivilegedPorts checks CIS 5.7: Ensure privileged ports are not mapped
func (a *CISBenchmarkAnalyzer) checkPrivilegedPorts(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	for _, port := range data.Ports {
		if port.HostPort > 0 && port.HostPort < 1024 {
			issue := security.Issue{
				CheckID:  CISCheckPrivilegedPorts,
				Severity: models.IssueSeverityMedium,
				Category: models.IssueCategorySecurity,
				Title:    fmt.Sprintf("CIS 5.7: Privileged Port %d Mapped", port.HostPort),
				Description: fmt.Sprintf("Container '%s' maps privileged port %d on the host. "+
					"Privileged ports (below 1024) traditionally require root privileges.",
					data.Name, port.HostPort),
				Recommendation: "Use ports above 1024 and configure a reverse proxy if needed.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        5,
			}
			issues = append(issues, issue.WithDetail("host_port", port.HostPort).WithDetail("container_port", port.ContainerPort).WithDetail("container", data.Name))
		}
	}

	return issues
}

// checkHostNetworkMode checks CIS 5.9: Ensure the host's network namespace is not shared
func (a *CISBenchmarkAnalyzer) checkHostNetworkMode(data *security.ContainerData) []security.Issue {
	if data.NetworkMode == "host" {
		issue := security.Issue{
			CheckID:  CISCheckHostNetworkMode,
			Severity: models.IssueSeverityHigh,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.9: Host Network Mode Enabled",
			Description: fmt.Sprintf("Container '%s' shares the host's network namespace. "+
				"This disables network isolation and allows the container to access all "+
				"network interfaces and services on the host.", data.Name),
			Recommendation: "Use bridge networking (default) or create a custom network. " +
				"Only use host network mode if absolutely necessary.",
			DocURL:  "https://www.cisecurity.org/benchmark/docker",
			Penalty: 15,
		}
		return []security.Issue{issue.WithDetail("network_mode", data.NetworkMode).WithDetail("container", data.Name)}
	}
	return nil
}

// checkMemoryLimit checks CIS 5.10: Ensure memory usage for containers is limited
func (a *CISBenchmarkAnalyzer) checkMemoryLimit(data *security.ContainerData) []security.Issue {
	if data.MemoryLimit == 0 {
		issue := security.Issue{
			CheckID:  CISCheckMemoryLimit,
			Severity: models.IssueSeverityMedium,
			Category: models.IssueCategoryReliability,
			Title:    "CIS 5.10: No Memory Limit Set",
			Description: fmt.Sprintf("Container '%s' has no memory limit configured. "+
				"Without memory limits, a container can consume all available host memory, "+
				"leading to denial of service.", data.Name),
			Recommendation: "Set appropriate memory limits using --memory flag.",
			FixCommand:     fmt.Sprintf("docker update --memory 512m %s", data.Name),
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        8,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkCPUPriority checks CIS 5.11: Ensure CPU priority is set appropriately
func (a *CISBenchmarkAnalyzer) checkCPUPriority(data *security.ContainerData) []security.Issue {
	hasCPULimit := data.NanoCPUs > 0 || data.CPUQuota > 0 || data.CPUShares > 0

	if !hasCPULimit && a.StrictMode {
		issue := security.Issue{
			CheckID:  CISCheckCPUPriority,
			Severity: models.IssueSeverityLow,
			Category: models.IssueCategoryReliability,
			Title:    "CIS 5.11: No CPU Limit Set",
			Description: fmt.Sprintf("Container '%s' has no CPU limit configured. "+
				"A runaway process could consume all CPU resources.", data.Name),
			Recommendation: "Set CPU limits using --cpus flag.",
			FixCommand:     fmt.Sprintf("docker update --cpus 1.0 %s", data.Name),
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        3,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkReadOnlyRootFS checks CIS 5.12: Ensure container's root filesystem is mounted as read only
func (a *CISBenchmarkAnalyzer) checkReadOnlyRootFS(data *security.ContainerData) []security.Issue {
	if !data.ReadonlyRootfs {
		severity := models.IssueSeverityLow
		if a.StrictMode {
			severity = models.IssueSeverityMedium
		}
		issue := security.Issue{
			CheckID:  CISCheckReadOnlyRootFS,
			Severity: severity,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.12: Root Filesystem is Writable",
			Description: fmt.Sprintf("Container '%s' has a writable root filesystem. "+
				"A read-only filesystem prevents attackers from modifying container files.", data.Name),
			Recommendation: "Use --read-only flag and mount specific writable directories as needed.",
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        5,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkBindHostInterface checks CIS 5.13: Ensure incoming container traffic is bound to specific host interface
func (a *CISBenchmarkAnalyzer) checkBindHostInterface(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	for _, port := range data.Ports {
		if port.HostPort > 0 && (port.HostIP == "" || port.HostIP == "0.0.0.0") {
			issue := security.Issue{
				CheckID:  CISCheckBindHostInterface,
				Severity: models.IssueSeverityMedium,
				Category: models.IssueCategoryNetwork,
				Title:    "CIS 5.13: Port Bound to All Interfaces",
				Description: fmt.Sprintf("Container '%s' port %d is bound to all host interfaces (0.0.0.0). "+
					"This exposes the service to all network interfaces.", data.Name, port.HostPort),
				Recommendation: "Bind to specific interface: -p 127.0.0.1:8080:80 or use internal networks.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        5,
			}
			issues = append(issues, issue.WithDetail("host_port", port.HostPort).WithDetail("host_ip", port.HostIP).WithDetail("container", data.Name))
		}
	}

	return issues
}

// checkRestartPolicy checks CIS 5.14: Ensure 'on-failure' restart policy is set to '5'
func (a *CISBenchmarkAnalyzer) checkRestartPolicy(data *security.ContainerData) []security.Issue {
	if data.RestartPolicy == "always" {
		issue := security.Issue{
			CheckID:  CISCheckRestartPolicy,
			Severity: models.IssueSeverityLow,
			Category: models.IssueCategoryReliability,
			Title:    "CIS 5.14: Unlimited Restart Policy",
			Description: fmt.Sprintf("Container '%s' uses 'always' restart policy without a maximum retry limit. "+
				"A failing container could cause excessive restarts.", data.Name),
			Recommendation: "Use 'on-failure' restart policy with max retries: --restart on-failure:5",
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        2,
		}
		return []security.Issue{issue.WithDetail("restart_policy", data.RestartPolicy).WithDetail("container", data.Name)}
	}
	return nil
}

// checkHostPIDNamespace checks CIS 5.15: Ensure host's process namespace is not shared
func (a *CISBenchmarkAnalyzer) checkHostPIDNamespace(data *security.ContainerData) []security.Issue {
	if data.PidMode == "host" {
		issue := security.Issue{
			CheckID:  CISCheckHostPIDNamespace,
			Severity: models.IssueSeverityHigh,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.15: Host PID Namespace Shared",
			Description: fmt.Sprintf("Container '%s' shares the host's PID namespace. "+
				"This allows the container to see and potentially interact with all host processes, "+
				"breaking process isolation.", data.Name),
			Recommendation: "Remove --pid=host unless absolutely necessary for debugging.",
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        15,
		}
		return []security.Issue{issue.WithDetail("pid_mode", data.PidMode).WithDetail("container", data.Name)}
	}
	return nil
}

// checkHostIPCNamespace checks CIS 5.16: Ensure host's IPC namespace is not shared
func (a *CISBenchmarkAnalyzer) checkHostIPCNamespace(data *security.ContainerData) []security.Issue {
	if data.IpcMode == "host" {
		issue := security.Issue{
			CheckID:  CISCheckHostIPCNamespace,
			Severity: models.IssueSeverityHigh,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.16: Host IPC Namespace Shared",
			Description: fmt.Sprintf("Container '%s' shares the host's IPC namespace. "+
				"This allows the container to access shared memory segments on the host, "+
				"potentially leaking sensitive data.", data.Name),
			Recommendation: "Remove --ipc=host unless required for specific IPC needs.",
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        15,
		}
		return []security.Issue{issue.WithDetail("ipc_mode", data.IpcMode).WithDetail("container", data.Name)}
	}
	return nil
}

// checkHostDevices checks CIS 5.17: Ensure host devices are not directly exposed
func (a *CISBenchmarkAnalyzer) checkHostDevices(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	// Check for dangerous device mounts in binds
	dangerousDevices := []string{"/dev/sda", "/dev/sdb", "/dev/mem", "/dev/kmem", "/dev/port"}

	for _, bind := range data.Binds {
		for _, device := range dangerousDevices {
			if strings.HasPrefix(bind, device) {
				issue := security.Issue{
					CheckID:  CISCheckHostDevices,
					Severity: models.IssueSeverityCritical,
					Category: models.IssueCategorySecurity,
					Title:    "CIS 5.17: Dangerous Device Exposed",
					Description: fmt.Sprintf("Container '%s' has access to host device '%s'. "+
						"Direct access to host devices can lead to complete host compromise.", data.Name, device),
					Recommendation: "Remove direct device access. Use proper device plugins or volumes instead.",
					DocURL:         "https://www.cisecurity.org/benchmark/docker",
					Penalty:        25,
				}
				issues = append(issues, issue.WithDetail("device", device).WithDetail("container", data.Name))
			}
		}
	}

	return issues
}

// checkMountPropagation checks CIS 5.19: Ensure mount propagation mode is not set to shared
func (a *CISBenchmarkAnalyzer) checkMountPropagation(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	for _, mount := range data.Mounts {
		if mount.Propagation == "shared" || mount.Propagation == "rshared" {
			issue := security.Issue{
				CheckID:  CISCheckMountPropagation,
				Severity: models.IssueSeverityMedium,
				Category: models.IssueCategorySecurity,
				Title:    "CIS 5.19: Shared Mount Propagation",
				Description: fmt.Sprintf("Container '%s' has shared mount propagation for '%s'. "+
					"This allows mounts made inside the container to propagate to the host.",
					data.Name, mount.Destination),
				Recommendation: "Use 'private' or 'slave' mount propagation instead of 'shared'.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        8,
			}
			issues = append(issues, issue.WithDetail("mount", mount.Destination).WithDetail("propagation", mount.Propagation).WithDetail("container", data.Name))
		}
	}

	return issues
}

// checkSeccompProfile checks CIS 5.21: Ensure default seccomp profile is not Disabled
func (a *CISBenchmarkAnalyzer) checkSeccompProfile(data *security.ContainerData) []security.Issue {
	for _, opt := range data.SecurityOpt {
		opt = strings.ToLower(opt)
		if strings.Contains(opt, "seccomp=unconfined") || strings.Contains(opt, "seccomp:unconfined") {
			issue := security.Issue{
				CheckID:  CISCheckSeccompDefault,
				Severity: models.IssueSeverityHigh,
				Category: models.IssueCategorySecurity,
				Title:    "CIS 5.21: Seccomp Profile Disabled",
				Description: fmt.Sprintf("Container '%s' has seccomp disabled (unconfined). "+
					"Seccomp limits the system calls a container can make, reducing attack surface.", data.Name),
				Recommendation: "Use the default seccomp profile or a custom restricted profile.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        15,
			}
			return []security.Issue{issue.WithDetail("security_opt", opt).WithDetail("container", data.Name)}
		}
	}
	return nil
}

// checkNoNewPrivileges checks CIS 5.25: Ensure container is restricted from acquiring additional privileges
func (a *CISBenchmarkAnalyzer) checkNoNewPrivileges(data *security.ContainerData) []security.Issue {
	hasNoNewPrivileges := false

	for _, opt := range data.SecurityOpt {
		opt = strings.ToLower(opt)
		if strings.Contains(opt, "no-new-privileges=true") ||
			strings.Contains(opt, "no-new-privileges:true") ||
			opt == "no-new-privileges" {
			hasNoNewPrivileges = true
			break
		}
	}

	if !hasNoNewPrivileges && a.StrictMode {
		issue := security.Issue{
			CheckID:  CISCheckNoNewPrivileges,
			Severity: models.IssueSeverityMedium,
			Category: models.IssueCategorySecurity,
			Title:    "CIS 5.25: No-New-Privileges Not Set",
			Description: fmt.Sprintf("Container '%s' can acquire new privileges via setuid/setgid binaries. "+
				"This allows privilege escalation inside the container.", data.Name),
			Recommendation: "Add --security-opt=no-new-privileges to prevent privilege escalation.",
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        8,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkPIDsLimit checks CIS 5.28: Ensure PIDs cgroup limit is used
func (a *CISBenchmarkAnalyzer) checkPIDsLimit(data *security.ContainerData) []security.Issue {
	if data.PidsLimit == 0 {
		issue := security.Issue{
			CheckID:  CISCheckPIDCgroup,
			Severity: models.IssueSeverityLow,
			Category: models.IssueCategoryReliability,
			Title:    "CIS 5.28: No PIDs Limit Set",
			Description: fmt.Sprintf("Container '%s' has no PIDs limit. "+
				"A fork bomb attack could exhaust system process resources.", data.Name),
			Recommendation: "Set a PIDs limit with --pids-limit flag.",
			FixCommand:     fmt.Sprintf("docker update --pids-limit 200 %s", data.Name),
			DocURL:         "https://www.cisecurity.org/benchmark/docker",
			Penalty:        3,
		}
		return []security.Issue{issue.WithDetail("container", data.Name)}
	}
	return nil
}

// checkDefaultBridgeNetwork checks CIS 5.29: Ensure Docker's default bridge is not used
func (a *CISBenchmarkAnalyzer) checkDefaultBridgeNetwork(data *security.ContainerData) []security.Issue {
	for _, network := range data.Networks {
		if network.Name == "bridge" && a.StrictMode {
			issue := security.Issue{
				CheckID:  CISCheckBridgeNetwork,
				Severity: models.IssueSeverityLow,
				Category: models.IssueCategoryNetwork,
				Title:    "CIS 5.29: Default Bridge Network Used",
				Description: fmt.Sprintf("Container '%s' is connected to the default bridge network. "+
					"The default bridge has limited isolation between containers.", data.Name),
				Recommendation: "Create and use user-defined bridge networks for better isolation.",
				DocURL:         "https://www.cisecurity.org/benchmark/docker",
				Penalty:        2,
			}
			return []security.Issue{issue.WithDetail("network", network.Name).WithDetail("container", data.Name)}
		}
	}
	return nil
}

// checkDockerSocket checks CIS 5.31: Ensure Docker socket is not mounted inside containers
func (a *CISBenchmarkAnalyzer) checkDockerSocket(data *security.ContainerData) []security.Issue {
	dockerSocketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/docker",
	}

	for _, mount := range data.Mounts {
		for _, socketPath := range dockerSocketPaths {
			if mount.Source == socketPath || strings.HasPrefix(mount.Source, socketPath) {
				issue := security.Issue{
					CheckID:  CISCheckDockerSocket,
					Severity: models.IssueSeverityCritical,
					Category: models.IssueCategorySecurity,
					Title:    "CIS 5.31: Docker Socket Mounted",
					Description: fmt.Sprintf("Container '%s' has the Docker socket mounted at '%s'. "+
						"This gives the container full control over the Docker daemon, "+
						"equivalent to root access on the host.", data.Name, mount.Destination),
					Recommendation: "Remove Docker socket mount. Use Docker-in-Docker or Docker socket proxy if needed.",
					DocURL:         "https://www.cisecurity.org/benchmark/docker",
					Penalty:        30,
				}
				return []security.Issue{issue.WithDetail("source", mount.Source).WithDetail("destination", mount.Destination).WithDetail("container", data.Name)}
			}
		}
	}

	// Also check Binds
	for _, bind := range data.Binds {
		for _, socketPath := range dockerSocketPaths {
			if strings.HasPrefix(bind, socketPath) {
				issue := security.Issue{
					CheckID:  CISCheckDockerSocket,
					Severity: models.IssueSeverityCritical,
					Category: models.IssueCategorySecurity,
					Title:    "CIS 5.31: Docker Socket Mounted",
					Description: fmt.Sprintf("Container '%s' has the Docker socket mounted. "+
						"This gives the container full control over the Docker daemon.", data.Name),
					Recommendation: "Remove Docker socket mount. Use Docker socket proxy if needed.",
					DocURL:         "https://www.cisecurity.org/benchmark/docker",
					Penalty:        30,
				}
				return []security.Issue{issue.WithDetail("bind", bind).WithDetail("container", data.Name)}
			}
		}
	}

	return nil
}

// GetPassedChecks returns a summary of passed CIS checks
func (a *CISBenchmarkAnalyzer) GetPassedChecks(data *security.ContainerData) []CISCheck {
	var passed []CISCheck

	// Check each CIS requirement and add to passed if no issues
	if !isRootUser(data.User) {
		passed = append(passed, CISCheck{
			ID:    CISCheckContainerUser,
			Title: "Container runs as non-root user",
		})
	}

	if !data.Privileged {
		passed = append(passed, CISCheck{
			ID:    CISCheckPrivileged,
			Title: "Privileged mode is disabled",
		})
	}

	if data.MemoryLimit > 0 {
		passed = append(passed, CISCheck{
			ID:    CISCheckMemoryLimit,
			Title: "Memory limit is configured",
		})
	}

	if data.ReadonlyRootfs {
		passed = append(passed, CISCheck{
			ID:    CISCheckReadOnlyRootFS,
			Title: "Root filesystem is read-only",
		})
	}

	if data.NetworkMode != "host" {
		passed = append(passed, CISCheck{
			ID:    CISCheckHostNetworkMode,
			Title: "Host network mode is not used",
		})
	}

	if data.PidMode != "host" {
		passed = append(passed, CISCheck{
			ID:    CISCheckHostPIDNamespace,
			Title: "Host PID namespace is not shared",
		})
	}

	if data.IpcMode != "host" {
		passed = append(passed, CISCheck{
			ID:    CISCheckHostIPCNamespace,
			Title: "Host IPC namespace is not shared",
		})
	}

	return passed
}

// CISSummary holds a summary of the CIS benchmark results
type CISSummary struct {
	TotalChecks  int
	PassedChecks int
	FailedChecks int
	Score        float64
	Grade        string
}

// GetSummary returns a summary of the CIS benchmark analysis
func (a *CISBenchmarkAnalyzer) GetSummary(data *security.ContainerData, issues []security.Issue) CISSummary {
	totalChecks := 22 // Total CIS checks implemented
	failedChecks := 0

	// Count unique failed checks
	failedIDs := make(map[string]bool)
	for _, issue := range issues {
		if strings.HasPrefix(issue.CheckID, "CIS-") {
			failedIDs[issue.CheckID] = true
		}
	}
	failedChecks = len(failedIDs)
	passedChecks := totalChecks - failedChecks

	score := float64(passedChecks) / float64(totalChecks) * 100

	var grade string
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return CISSummary{
		TotalChecks:  totalChecks,
		PassedChecks: passedChecks,
		FailedChecks: failedChecks,
		Score:        score,
		Grade:        grade,
	}
}
