// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package runtime provides a runtime threat detection service for Docker
// containers. It monitors running processes inside containers, evaluates
// them against configurable security rules, learns behavioral baselines,
// and generates security events when anomalies or policy violations are
// detected.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/host"
)

// ============================================================================
// Repository interface
// ============================================================================

// Repository defines the persistence operations required by the runtime
// threat detection service. It mirrors the postgres.RuntimeSecurityRepository
// contract so that alternative implementations can be swapped in for testing.
type Repository interface {
	// Event operations
	CreateEvent(ctx context.Context, event *models.RuntimeSecurityEvent) error
	CreateEventBatch(ctx context.Context, events []*models.RuntimeSecurityEvent) error
	ListEvents(ctx context.Context, opts postgres.RuntimeEventListOptions) ([]*models.RuntimeSecurityEvent, int64, error)
	AcknowledgeEvent(ctx context.Context, eventID int64, userID uuid.UUID) error
	GetEventStats(ctx context.Context, since time.Time) (*postgres.RuntimeEventStats, error)
	DeleteOldEvents(ctx context.Context, retention time.Duration) (int64, error)

	// Rule operations
	CreateRule(ctx context.Context, rule *models.RuntimeSecurityRule) error
	GetRule(ctx context.Context, id uuid.UUID) (*models.RuntimeSecurityRule, error)
	ListRules(ctx context.Context) ([]*models.RuntimeSecurityRule, error)
	UpdateRule(ctx context.Context, rule *models.RuntimeSecurityRule) error
	DeleteRule(ctx context.Context, id uuid.UUID) error
	ToggleRule(ctx context.Context, id uuid.UUID, enabled bool) error
	IncrementRuleEventCount(ctx context.Context, ruleID uuid.UUID) error

	// Baseline operations
	CreateBaseline(ctx context.Context, baseline *models.RuntimeBaseline) error
	GetActiveBaseline(ctx context.Context, containerID string, baselineType string) (*models.RuntimeBaseline, error)
	UpdateBaseline(ctx context.Context, baseline *models.RuntimeBaseline) error
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds the runtime threat detection service configuration.
type Config struct {
	// Enabled controls whether monitoring is active.
	Enabled bool

	// Retention is how long events are kept before automatic cleanup.
	Retention time.Duration

	// MonitorInterval is how often the service scans running containers.
	MonitorInterval time.Duration

	// BaselineLearningPeriod is how long the service collects process
	// samples before finalizing a baseline.
	BaselineLearningPeriod time.Duration

	// BaselineMinSamples is the minimum number of process observations
	// required before a baseline is considered stable.
	BaselineMinSamples int
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:                true,
		Retention:              30 * 24 * time.Hour, // 30 days
		MonitorInterval:        1 * time.Minute,
		BaselineLearningPeriod: 24 * time.Hour,
		BaselineMinSamples:     100,
	}
}

// ============================================================================
// Supporting types
// ============================================================================

// DashboardData contains the summary data rendered on the runtime security
// dashboard.
type DashboardData struct {
	TotalEvents    int64                          `json:"total_events"`
	SeverityCounts map[string]int                 `json:"severity_counts"`
	TypeCounts     map[string]int                 `json:"type_counts"`
	TopContainers  []postgres.ContainerEventCount `json:"top_containers"`
	RecentEvents   []*models.RuntimeSecurityEvent `json:"recent_events"`
}

// ProcessInfo describes a single process observed inside a container.
type ProcessInfo struct {
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	Cmdline   string `json:"cmdline"`
	User      string `json:"user"`
	ParentPID int    `json:"parent_pid"`
}

// RuleDefinition is the JSON schema stored in RuntimeSecurityRule.Definition.
type RuleDefinition struct {
	// ProcessNames are exact process names to match (e.g. "bash", "sh").
	ProcessNames []string `json:"process_names,omitempty"`
	// ProcessPatterns are substring patterns matched against the full cmdline.
	ProcessPatterns []string `json:"process_patterns,omitempty"`
	// FilePatterns are path substrings matched when the event type is file_access.
	FilePatterns []string `json:"file_patterns,omitempty"`
}

// baselineData is serialized into RuntimeBaseline.BaselineData.
type baselineData struct {
	Processes map[string]int `json:"processes"` // process name -> seen count
}

// ============================================================================
// Service
// ============================================================================

// Service is the runtime threat detection service. It monitors container
// processes, evaluates security rules, and manages behavioral baselines.
type Service struct {
	repo        Repository
	hostService *host.Service
	config      Config
	logger      *logger.Logger
}

// NewService creates a new runtime threat detection service.
func NewService(
	repo Repository,
	hostService *host.Service,
	config Config,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:        repo,
		hostService: hostService,
		config:      config,
		logger:      log.Named("runtime"),
	}
}

// ============================================================================
// Public query API
// ============================================================================

// ListEvents retrieves runtime security events with filtering and pagination.
func (s *Service) ListEvents(ctx context.Context, opts postgres.RuntimeEventListOptions) ([]*models.RuntimeSecurityEvent, int64, error) {
	return s.repo.ListEvents(ctx, opts)
}

// AcknowledgeEvent marks a runtime security event as acknowledged by the
// given user.
func (s *Service) AcknowledgeEvent(ctx context.Context, eventID int64, userID uuid.UUID) error {
	return s.repo.AcknowledgeEvent(ctx, eventID, userID)
}

// ListRules retrieves all runtime security rules.
func (s *Service) ListRules(ctx context.Context) ([]*models.RuntimeSecurityRule, error) {
	return s.repo.ListRules(ctx)
}

// ============================================================================
// Dashboard
// ============================================================================

// GetDashboardData assembles the summary data for the runtime security
// dashboard. It aggregates statistics for the last 24 hours.
func (s *Service) GetDashboardData(ctx context.Context) (*DashboardData, error) {
	since := time.Now().Add(-24 * time.Hour)

	stats, err := s.repo.GetEventStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("get event stats: %w", err)
	}

	// Fetch most recent events for the dashboard feed.
	recentEvents, _, err := s.repo.ListEvents(ctx, postgres.RuntimeEventListOptions{
		Limit: 20,
	})
	if err != nil {
		return nil, fmt.Errorf("list recent events: %w", err)
	}

	dashboard := &DashboardData{
		TotalEvents:    stats.TotalEvents,
		SeverityCounts: stats.SeverityCounts,
		TypeCounts:     stats.TypeCounts,
		TopContainers:  stats.TopContainers,
		RecentEvents:   recentEvents,
	}

	return dashboard, nil
}

// ============================================================================
// Container monitoring
// ============================================================================

// MonitorAllContainers runs runtime checks against all running containers
// on the specified host.
func (s *Service) MonitorAllContainers(ctx context.Context, hostID uuid.UUID) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get docker client for host %s: %w", hostID, err)
	}

	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{
		All: false, // only running containers
	})
	if err != nil {
		return fmt.Errorf("list containers on host %s: %w", hostID, err)
	}

	var errs []string
	for _, c := range containers {
		if c.State != "running" {
			continue
		}
		if monErr := s.MonitorContainer(ctx, hostID, c.ID); monErr != nil {
			errs = append(errs, fmt.Sprintf("container %s: %v", c.ID[:12], monErr))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors monitoring containers: %s", strings.Join(errs, "; "))
	}
	return nil
}

// MonitorContainer inspects a single container's running processes and
// evaluates them against the enabled security rules. Any matches are
// persisted as RuntimeSecurityEvents. If the container has an active
// baseline in learning mode the process observations are recorded; if
// the baseline is complete, unknown processes generate anomaly events.
func (s *Service) MonitorContainer(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get docker client for host %s: %w", hostID, err)
	}

	// Get container metadata for event enrichment.
	details, err := client.ContainerGet(ctx, containerID)
	if err != nil {
		return fmt.Errorf("inspect container %s: %w", containerID, err)
	}

	// Fetch running processes via the Docker top API.
	rows, err := client.ContainerTop(ctx, containerID, "")
	if err != nil {
		return fmt.Errorf("container top %s: %w", containerID, err)
	}

	processes := parseProcessRows(rows)

	// Load enabled rules.
	rules, err := s.repo.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	enabledRules := filterEnabledRules(rules)

	var allEvents []*models.RuntimeSecurityEvent

	for _, proc := range processes {
		// --- Static rule evaluation ---
		for _, rule := range enabledRules {
			matched, matchErr := matchRule(rule, proc)
			if matchErr != nil {
				s.logger.Debug("Rule evaluation error",
					"rule_id", rule.ID,
					"error", matchErr)
				continue
			}
			if !matched {
				continue
			}

			detailsJSON, _ := json.Marshal(map[string]interface{}{
				"process_name": proc.Name,
				"cmdline":      proc.Cmdline,
				"pid":          proc.PID,
				"user":         proc.User,
				"parent_pid":   proc.ParentPID,
			})

			event := &models.RuntimeSecurityEvent{
				HostID:        &hostID,
				ContainerID:   containerID,
				ContainerName: details.Name,
				EventType:     rule.RuleType,
				Severity:      rule.Severity,
				RuleID:        rule.ID.String(),
				RuleName:      rule.Name,
				Description: fmt.Sprintf("Rule '%s' triggered: %s (pid=%d, user=%s, cmdline=%s)",
					rule.Name, proc.Name, proc.PID, proc.User, proc.Cmdline),
				Details:     detailsJSON,
				Source:      "runtime_monitor",
				ActionTaken: rule.Action,
				DetectedAt:  time.Now(),
			}
			allEvents = append(allEvents, event)

			// Increment the rule's hit counter.
			if incErr := s.repo.IncrementRuleEventCount(ctx, rule.ID); incErr != nil {
				s.logger.Debug("failed to increment rule event count", "rule_id", rule.ID, "error", incErr)
			}
		}

		// --- Baseline anomaly check ---
		anomaly, anomalyErr := s.checkAnomaly(ctx, containerID, details.Name, details.Image, proc)
		if anomalyErr != nil {
			s.logger.Debug("Anomaly check skipped",
				"container_id", containerID,
				"error", anomalyErr)
			continue
		}
		if anomaly != nil {
			anomaly.HostID = &hostID
			anomaly.ContainerName = details.Name
			allEvents = append(allEvents, anomaly)
		}
	}

	// Persist all generated events in a single batch.
	if len(allEvents) > 0 {
		if err := s.repo.CreateEventBatch(ctx, allEvents); err != nil {
			return fmt.Errorf("persist events for container %s: %w", containerID, err)
		}
	}

	return nil
}

// ============================================================================
// Rule matching
// ============================================================================

// matchRule determines whether a process matches a rule's definition.
func matchRule(rule *models.RuntimeSecurityRule, proc *ProcessInfo) (bool, error) {
	var def RuleDefinition
	if err := json.Unmarshal(rule.Definition, &def); err != nil {
		return false, fmt.Errorf("unmarshal rule definition %s: %w", rule.ID, err)
	}

	// Match exact process names.
	for _, name := range def.ProcessNames {
		if strings.EqualFold(proc.Name, name) {
			return true, nil
		}
	}

	// Match cmdline patterns (substring match).
	cmdlineLower := strings.ToLower(proc.Cmdline)
	for _, pattern := range def.ProcessPatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			return true, nil
		}
	}

	// Match file patterns (substring match against cmdline).
	for _, fp := range def.FilePatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(fp)) {
			return true, nil
		}
	}

	return false, nil
}

// filterEnabledRules returns only the rules that have IsEnabled set to true.
func filterEnabledRules(rules []*models.RuntimeSecurityRule) []*models.RuntimeSecurityRule {
	var enabled []*models.RuntimeSecurityRule
	for _, r := range rules {
		if r.IsEnabled {
			enabled = append(enabled, r)
		}
	}
	return enabled
}

// ============================================================================
// Baseline learning & anomaly detection
// ============================================================================

// checkAnomaly compares a process against the learned baseline for its
// container. If no baseline exists one is created in learning mode. If
// learning is still in progress the observation is recorded. If the baseline
// is complete, unknown processes generate anomaly events.
func (s *Service) checkAnomaly(ctx context.Context, containerID, containerName, image string, proc *ProcessInfo) (*models.RuntimeSecurityEvent, error) {
	baselineType := "process"

	baseline, err := s.repo.GetActiveBaseline(ctx, containerID, baselineType)
	if err != nil {
		return nil, fmt.Errorf("get baseline: %w", err)
	}

	// Start a new baseline if none exists.
	if baseline == nil {
		return nil, s.startBaseline(ctx, containerID, containerName, image, proc)
	}

	var data baselineData
	if err := json.Unmarshal(baseline.BaselineData, &data); err != nil {
		return nil, fmt.Errorf("unmarshal baseline data: %w", err)
	}

	// If we are still in the learning window, record the process and return.
	learningDeadline := baseline.LearningStartedAt.Add(s.config.BaselineLearningPeriod)
	if time.Now().Before(learningDeadline) || baseline.SampleCount < s.config.BaselineMinSamples {
		return s.updateBaselineLearning(ctx, baseline, &data, proc)
	}

	// Finalize baseline if not yet marked complete.
	if baseline.LearningCompletedAt == nil {
		now := time.Now()
		baseline.LearningCompletedAt = &now
		baseline.Confidence = calculateConfidence(data, baseline.SampleCount, s.config.BaselineMinSamples)
		if updateErr := s.repo.UpdateBaseline(ctx, baseline); updateErr != nil {
			s.logger.Warn("Failed to finalize baseline", "error", updateErr)
		}
	}

	// Only flag anomalies when we have reasonable confidence.
	if baseline.Confidence < 0.5 {
		return nil, nil
	}

	// Check whether the process is in the baseline.
	if _, known := data.Processes[proc.Name]; known {
		return nil, nil
	}

	// Unknown process detected -- create an anomaly event.
	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"process_name":        proc.Name,
		"cmdline":             proc.Cmdline,
		"pid":                 proc.PID,
		"user":                proc.User,
		"baseline_id":         baseline.ID,
		"baseline_confidence": baseline.Confidence,
		"baseline_processes":  len(data.Processes),
	})

	event := &models.RuntimeSecurityEvent{
		ContainerID: containerID,
		EventType:   models.RuntimeEventAnomaly,
		Severity:    "medium",
		RuleID:      "baseline-anomaly",
		RuleName:    "Baseline Anomaly Detection",
		Description: fmt.Sprintf("Unknown process '%s' detected (pid=%d, user=%s); not seen during baseline learning",
			proc.Name, proc.PID, proc.User),
		Details:     detailsJSON,
		Source:      "baseline_monitor",
		ActionTaken: "alert",
		DetectedAt:  time.Now(),
	}

	return event, nil
}

// startBaseline creates a new learning baseline for a container and records
// the first process observation.
func (s *Service) startBaseline(ctx context.Context, containerID, containerName, image string, proc *ProcessInfo) error {
	data := baselineData{Processes: map[string]int{proc.Name: 1}}
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal initial baseline data: %w", err)
	}

	baseline := &models.RuntimeBaseline{
		ContainerID:       containerID,
		ContainerName:     containerName,
		Image:             image,
		BaselineType:      "process",
		BaselineData:      dataJSON,
		SampleCount:       1,
		Confidence:        0.0,
		IsActive:          true,
		LearningStartedAt: time.Now(),
	}

	if err := s.repo.CreateBaseline(ctx, baseline); err != nil {
		return fmt.Errorf("create baseline: %w", err)
	}

	s.logger.Info("Baseline learning started",
		"container_id", containerID,
		"container_name", containerName,
		"image", image)

	return nil
}

// updateBaselineLearning records a process sample during the learning window.
func (s *Service) updateBaselineLearning(ctx context.Context, baseline *models.RuntimeBaseline, data *baselineData, proc *ProcessInfo) (*models.RuntimeSecurityEvent, error) {
	data.Processes[proc.Name]++
	baseline.SampleCount++

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal updated baseline data: %w", err)
	}
	baseline.BaselineData = dataJSON
	baseline.Confidence = calculateConfidence(*data, baseline.SampleCount, s.config.BaselineMinSamples)

	if err := s.repo.UpdateBaseline(ctx, baseline); err != nil {
		return nil, fmt.Errorf("update baseline during learning: %w", err)
	}

	return nil, nil // no anomaly during learning
}

// calculateConfidence produces a confidence score between 0 and 1 based on
// the number of unique processes and how many samples have been collected.
func calculateConfidence(data baselineData, sampleCount, minSamples int) float64 {
	if sampleCount == 0 {
		return 0
	}
	uniqueProcesses := len(data.Processes)
	if uniqueProcesses == 0 {
		return 0
	}

	// More samples and more unique processes increase confidence.
	sampleFactor := float64(sampleCount) / float64(minSamples)
	if sampleFactor > 1.0 {
		sampleFactor = 1.0
	}

	diversityFactor := float64(uniqueProcesses) / 10.0
	if diversityFactor > 1.0 {
		diversityFactor = 1.0
	}

	confidence := sampleFactor*0.7 + diversityFactor*0.3
	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

// ============================================================================
// Docker integration helpers
// ============================================================================

// parseProcessRows converts the tabular output from Docker ContainerTop into
// ProcessInfo structs. Each row is typically [UID, PID, PPID, C, STIME, TTY,
// TIME, CMD] but may vary, so we use best-effort parsing.
func parseProcessRows(rows [][]string) []*ProcessInfo {
	var processes []*ProcessInfo
	for _, row := range rows {
		proc := parseProcessRow(row)
		if proc != nil {
			processes = append(processes, proc)
		}
	}
	return processes
}

// parseProcessRow converts a single row from ContainerTop into a ProcessInfo.
func parseProcessRow(row []string) *ProcessInfo {
	if len(row) < 4 {
		return nil
	}

	proc := &ProcessInfo{}

	// Typical ps output: UID PID PPID C STIME TTY TIME CMD
	if len(row) >= 8 {
		proc.User = row[0]
		fmt.Sscanf(row[1], "%d", &proc.PID)
		fmt.Sscanf(row[2], "%d", &proc.ParentPID)
		proc.Cmdline = row[7]
		// For additional columns (arguments), join them.
		if len(row) > 8 {
			proc.Cmdline = strings.Join(row[7:], " ")
		}
	} else {
		// Fallback: treat first column as PID, last as CMD.
		fmt.Sscanf(row[0], "%d", &proc.PID)
		proc.Cmdline = row[len(row)-1]
	}

	// Extract the process name from the cmdline (basename of the first token).
	proc.Name = extractProcessName(proc.Cmdline)

	return proc
}

// extractProcessName returns the base name of the first token in a command line.
func extractProcessName(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}

	parts := strings.Fields(cmdline)
	first := parts[0]

	// Strip path prefix.
	if idx := strings.LastIndex(first, "/"); idx >= 0 {
		first = first[idx+1:]
	}

	return first
}

// ============================================================================
// Default rules seeding
// ============================================================================

// SeedDefaultRules populates the database with a standard set of detection
// rules if they do not already exist. Existing rules (matched by name) are
// not overwritten so that user customisations are preserved.
func (s *Service) SeedDefaultRules(ctx context.Context) error {
	existing, err := s.repo.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("list existing rules: %w", err)
	}

	existingNames := make(map[string]bool, len(existing))
	for _, r := range existing {
		existingNames[r.Name] = true
	}

	defaults := defaultRules()
	var created int
	for _, rule := range defaults {
		if existingNames[rule.Name] {
			continue
		}
		if err := s.repo.CreateRule(ctx, rule); err != nil {
			s.logger.Warn("Failed to seed default rule",
				"rule", rule.Name,
				"error", err)
			continue
		}
		created++
	}

	if created > 0 {
		s.logger.Info("Seeded default runtime security rules", "count", created)
	}

	return nil
}

// defaultRules returns the ten built-in detection rules.
func defaultRules() []*models.RuntimeSecurityRule {
	mustJSON := func(v interface{}) json.RawMessage {
		b, _ := json.Marshal(v)
		return b
	}

	return []*models.RuntimeSecurityRule{
		{
			Name:        "detect-reverse-shell",
			Description: "Detect reverse shell patterns such as netcat listeners, bash TCP redirects, and named pipes",
			Category:    "intrusion",
			RuleType:    "process",
			Severity:    "critical",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames:    []string{"nc", "ncat", "nmap", "socat"},
				ProcessPatterns: []string{"nc -e", "nc -l", "ncat -e", "bash -i >& /dev/tcp", "socat exec:", "/dev/tcp/", "/dev/udp/", "mkfifo /tmp"},
			}),
		},
		{
			Name:        "detect-cryptominer",
			Description: "Detect known cryptocurrency mining processes and stratum pool connections",
			Category:    "malware",
			RuleType:    "process",
			Severity:    "critical",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames:    []string{"xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer", "nbminer", "t-rex", "phoenixminer"},
				ProcessPatterns: []string{"stratum+tcp", "stratum+ssl", "pool.minexmr", "monerohash", "cryptonight", "nicehash"},
			}),
		},
		{
			Name:        "detect-privilege-escalation",
			Description: "Detect privilege escalation attempts via sudo, su, setuid changes, or ownership manipulation",
			Category:    "privilege_escalation",
			RuleType:    "process",
			Severity:    "critical",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames:    []string{"sudo", "su", "doas"},
				ProcessPatterns: []string{"chmod +s", "chmod u+s", "chmod g+s", "setuid", "setgid", "chown root"},
			}),
		},
		{
			Name:        "detect-sensitive-file-access",
			Description: "Detect access to sensitive system files including credentials, SSH keys, and password databases",
			Category:    "file_access",
			RuleType:    "file",
			Severity:    "high",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				FilePatterns: []string{"/etc/shadow", "/etc/passwd", "/etc/master.passwd", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/authorized_keys", "/root/.ssh", "private.key", "private.pem"},
			}),
		},
		{
			Name:        "detect-binary-modification",
			Description: "Detect modifications to system binaries or installation of new executables in standard paths",
			Category:    "file_integrity",
			RuleType:    "file",
			Severity:    "high",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessPatterns: []string{"cp /", "mv /", "install -m", "chmod +x /usr", "chmod +x /bin", "chmod +x /sbin"},
				FilePatterns:    []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/"},
			}),
		},
		{
			Name:        "detect-unexpected-network",
			Description: "Detect unexpected outbound network connections via common download or tunneling tools",
			Category:    "network",
			RuleType:    "network",
			Severity:    "medium",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames:    []string{"wget", "curl", "ssh", "scp", "sftp", "telnet"},
				ProcessPatterns: []string{"wget http", "curl http", "wget --no-check-certificate", "curl -k http", "ssh -R", "ssh -L"},
			}),
		},
		{
			Name:        "detect-container-escape-attempt",
			Description: "Detect container escape attempts via mount namespace manipulation, cgroup abuse, or Docker socket access",
			Category:    "container_escape",
			RuleType:    "behavior",
			Severity:    "critical",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessPatterns: []string{
					"nsenter", "mount /proc", "mount -t cgroup",
					"/proc/1/root", "/proc/sysrq-trigger",
					"release_agent", "notify_on_release",
					"/.dockerenv", "/var/run/docker.sock",
					"capsh --print", "unshare --mount",
				},
			}),
		},
		{
			Name:        "detect-package-installation",
			Description: "Detect runtime package manager execution which may indicate supply chain compromise or image drift",
			Category:    "process_execution",
			RuleType:    "process",
			Severity:    "high",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames: []string{"apt", "apt-get", "yum", "dnf", "apk", "pip", "pip3", "npm", "yarn", "gem", "dpkg", "rpm"},
			}),
		},
		{
			Name:        "detect-suspicious-env-var",
			Description: "Detect processes that manipulate or exfiltrate environment variables which may contain secrets",
			Category:    "data_exfiltration",
			RuleType:    "behavior",
			Severity:    "medium",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessPatterns: []string{"printenv", "env | ", "set | ", "export | ", "/proc/self/environ", "/proc/*/environ", "AWS_SECRET", "DATABASE_URL", "API_KEY"},
			}),
		},
		{
			Name:        "detect-lateral-movement",
			Description: "Detect tools and patterns associated with lateral movement within a container network",
			Category:    "reconnaissance",
			RuleType:    "network",
			Severity:    "high",
			Action:      "alert",
			IsEnabled:   true,
			Definition: mustJSON(RuleDefinition{
				ProcessNames:    []string{"nmap", "masscan", "zmap", "zgrab", "rustscan", "ping"},
				ProcessPatterns: []string{"nmap -s", "masscan -p", "zmap -p", "arp -a", "ip neigh", "hostname -I", "ifconfig", "ip addr"},
			}),
		},
	}
}
