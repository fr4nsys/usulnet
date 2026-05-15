// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Business Metrics Collector
// ============================================================================

// BusinessMetrics tracks domain-specific metrics for the usulnet platform.
// These complement the infrastructure-level host/container metrics with
// business-relevant counters, gauges and histograms.
type BusinessMetrics struct {
	mu sync.RWMutex

	// Gauges - current values
	AgentsConnected   int
	ContainersByState map[string]int            // state -> count (running, stopped, paused, etc.)
	ContainersByHost  map[string]map[string]int // hostID -> state -> count
	ImagesWithVulns   map[string]int            // severity -> count (critical, high, medium, low)
	// LicenseType labels the optional commercial support tier reported
	// to Prometheus. It is purely informational — the AGPL build runs
	// every feature regardless of the value.
	LicenseType     string
	LicenseDaysLeft int // -1 if no license

	// Counters - monotonically increasing
	BackupsTotal       map[string]int64 // status -> count ("success", "failure")
	SecurityScansTotal map[string]int64 // status -> count ("completed", "failed")
	APIRequestsTotal   map[string]int64 // method:status -> count
	AuthAttemptsTotal  map[string]int64 // result -> count ("success", "failure", "locked")

	// Histograms - tracked as recent samples for summary stats
	DockerOpDurations map[string]*durationTracker // operation -> tracker
	APILatencies      map[string]*durationTracker // route -> tracker
}

// durationTracker keeps a sliding window of duration samples for computing
// summary statistics (count, sum, average).
type durationTracker struct {
	count int64
	sum   float64
}

// NewBusinessMetrics creates a new business metrics collector with initialized maps.
func NewBusinessMetrics() *BusinessMetrics {
	return &BusinessMetrics{
		ContainersByState:  make(map[string]int),
		ContainersByHost:   make(map[string]map[string]int),
		ImagesWithVulns:    make(map[string]int),
		BackupsTotal:       make(map[string]int64),
		SecurityScansTotal: make(map[string]int64),
		APIRequestsTotal:   make(map[string]int64),
		AuthAttemptsTotal:  make(map[string]int64),
		DockerOpDurations:  make(map[string]*durationTracker),
		APILatencies:       make(map[string]*durationTracker),
		LicenseType:        "community",
		LicenseDaysLeft:    -1,
	}
}

// RecordAgentsConnected sets the current number of connected agents.
func (bm *BusinessMetrics) RecordAgentsConnected(count int) {
	bm.mu.Lock()
	bm.AgentsConnected = count
	bm.mu.Unlock()
}

// RecordContainersByState updates the total containers by state.
func (bm *BusinessMetrics) RecordContainersByState(state string, count int) {
	bm.mu.Lock()
	bm.ContainersByState[state] = count
	bm.mu.Unlock()
}

// RecordContainersByHostState updates containers per host and state.
func (bm *BusinessMetrics) RecordContainersByHostState(hostID, state string, count int) {
	bm.mu.Lock()
	if bm.ContainersByHost[hostID] == nil {
		bm.ContainersByHost[hostID] = make(map[string]int)
	}
	bm.ContainersByHost[hostID][state] = count
	bm.mu.Unlock()
}

// RecordVulnerabilities updates vulnerability counts by severity.
func (bm *BusinessMetrics) RecordVulnerabilities(severity string, count int) {
	bm.mu.Lock()
	bm.ImagesWithVulns[strings.ToLower(severity)] = count
	bm.mu.Unlock()
}

// RecordBackup increments the backup counter for the given status.
func (bm *BusinessMetrics) RecordBackup(status string) {
	bm.mu.Lock()
	bm.BackupsTotal[status]++
	bm.mu.Unlock()
}

// RecordSecurityScan increments the security scan counter.
func (bm *BusinessMetrics) RecordSecurityScan(status string) {
	bm.mu.Lock()
	bm.SecurityScansTotal[status]++
	bm.mu.Unlock()
}

// RecordAPIRequest increments the API request counter.
func (bm *BusinessMetrics) RecordAPIRequest(method string, statusCode int) {
	key := fmt.Sprintf("%s:%d", method, statusCode)
	bm.mu.Lock()
	bm.APIRequestsTotal[key]++
	bm.mu.Unlock()
}

// RecordAuthAttempt increments the authentication attempt counter.
func (bm *BusinessMetrics) RecordAuthAttempt(result string) {
	bm.mu.Lock()
	bm.AuthAttemptsTotal[result]++
	bm.mu.Unlock()
}

// RecordDockerOpDuration records the duration of a Docker operation.
func (bm *BusinessMetrics) RecordDockerOpDuration(operation string, d time.Duration) {
	bm.mu.Lock()
	t := bm.DockerOpDurations[operation]
	if t == nil {
		t = &durationTracker{}
		bm.DockerOpDurations[operation] = t
	}
	t.count++
	t.sum += d.Seconds()
	bm.mu.Unlock()
}

// RecordAPILatency records the latency of an API request.
func (bm *BusinessMetrics) RecordAPILatency(route string, d time.Duration) {
	bm.mu.Lock()
	t := bm.APILatencies[route]
	if t == nil {
		t = &durationTracker{}
		bm.APILatencies[route] = t
	}
	t.count++
	t.sum += d.Seconds()
	bm.mu.Unlock()
}

// RecordLicenseInfo updates the current license type and days remaining.
func (bm *BusinessMetrics) RecordLicenseInfo(licType string, daysLeft int) {
	bm.mu.Lock()
	bm.LicenseType = licType
	bm.LicenseDaysLeft = daysLeft
	bm.mu.Unlock()
}

// FormatPrometheus renders business metrics in Prometheus text exposition format.
func (bm *BusinessMetrics) FormatPrometheus() string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	var b strings.Builder

	// --- Gauges ---

	// Agents connected
	writeSimpleGauge(&b, "usulnet_agents_connected_total",
		"Number of currently connected agents", float64(bm.AgentsConnected))

	// Containers by state
	if len(bm.ContainersByState) > 0 {
		b.WriteString("# HELP usulnet_containers_by_state Total containers by state\n")
		b.WriteString("# TYPE usulnet_containers_by_state gauge\n")
		for state, count := range bm.ContainersByState {
			fmt.Fprintf(&b, "usulnet_containers_by_state{state=\"%s\"} %d\n",
				sanitizeLabel(state), count)
		}
		b.WriteByte('\n')
	}

	// Containers by host and state
	if len(bm.ContainersByHost) > 0 {
		b.WriteString("# HELP usulnet_containers_by_host Containers per host by state\n")
		b.WriteString("# TYPE usulnet_containers_by_host gauge\n")
		for hostID, states := range bm.ContainersByHost {
			for state, count := range states {
				fmt.Fprintf(&b, "usulnet_containers_by_host{host=\"%s\",state=\"%s\"} %d\n",
					sanitizeLabel(hostID), sanitizeLabel(state), count)
			}
		}
		b.WriteByte('\n')
	}

	// Vulnerabilities by severity
	if len(bm.ImagesWithVulns) > 0 {
		b.WriteString("# HELP usulnet_vulnerabilities_total Known vulnerabilities by severity\n")
		b.WriteString("# TYPE usulnet_vulnerabilities_total gauge\n")
		for severity, count := range bm.ImagesWithVulns {
			fmt.Fprintf(&b, "usulnet_vulnerabilities_total{severity=\"%s\"} %d\n",
				sanitizeLabel(severity), count)
		}
		b.WriteByte('\n')
	}

	// License info
	writeSimpleGauge(&b, "usulnet_license_days_remaining",
		"Days until license expiration (-1 if no license)", float64(bm.LicenseDaysLeft))
	b.WriteString("# HELP usulnet_license_info License type information\n")
	b.WriteString("# TYPE usulnet_license_info gauge\n")
	fmt.Fprintf(&b, "usulnet_license_info{type=\"%s\"} 1\n\n", sanitizeLabel(bm.LicenseType))

	// --- Counters ---

	// Backups total
	if len(bm.BackupsTotal) > 0 {
		b.WriteString("# HELP usulnet_backups_total Total backups by status\n")
		b.WriteString("# TYPE usulnet_backups_total counter\n")
		for status, count := range bm.BackupsTotal {
			fmt.Fprintf(&b, "usulnet_backups_total{status=\"%s\"} %d\n",
				sanitizeLabel(status), count)
		}
		b.WriteByte('\n')
	}

	// Security scans total
	if len(bm.SecurityScansTotal) > 0 {
		b.WriteString("# HELP usulnet_security_scans_total Total security scans by status\n")
		b.WriteString("# TYPE usulnet_security_scans_total counter\n")
		for status, count := range bm.SecurityScansTotal {
			fmt.Fprintf(&b, "usulnet_security_scans_total{status=\"%s\"} %d\n",
				sanitizeLabel(status), count)
		}
		b.WriteByte('\n')
	}

	// API requests total
	if len(bm.APIRequestsTotal) > 0 {
		b.WriteString("# HELP usulnet_api_requests_total Total API requests by method and status\n")
		b.WriteString("# TYPE usulnet_api_requests_total counter\n")
		for key, count := range bm.APIRequestsTotal {
			parts := strings.SplitN(key, ":", 2)
			method := parts[0]
			status := "unknown"
			if len(parts) > 1 {
				status = parts[1]
			}
			fmt.Fprintf(&b, "usulnet_api_requests_total{method=\"%s\",status=\"%s\"} %d\n",
				sanitizeLabel(method), sanitizeLabel(status), count)
		}
		b.WriteByte('\n')
	}

	// Auth attempts total
	if len(bm.AuthAttemptsTotal) > 0 {
		b.WriteString("# HELP usulnet_auth_attempts_total Total authentication attempts by result\n")
		b.WriteString("# TYPE usulnet_auth_attempts_total counter\n")
		for result, count := range bm.AuthAttemptsTotal {
			fmt.Fprintf(&b, "usulnet_auth_attempts_total{result=\"%s\"} %d\n",
				sanitizeLabel(result), count)
		}
		b.WriteByte('\n')
	}

	// --- Summaries (from duration trackers) ---

	// Docker operation durations
	if len(bm.DockerOpDurations) > 0 {
		b.WriteString("# HELP usulnet_docker_operation_duration_seconds Duration of Docker operations\n")
		b.WriteString("# TYPE usulnet_docker_operation_duration_seconds summary\n")
		for op, t := range bm.DockerOpDurations {
			fmt.Fprintf(&b, "usulnet_docker_operation_duration_seconds_count{operation=\"%s\"} %d\n",
				sanitizeLabel(op), t.count)
			fmt.Fprintf(&b, "usulnet_docker_operation_duration_seconds_sum{operation=\"%s\"} %.6f\n",
				sanitizeLabel(op), t.sum)
		}
		b.WriteByte('\n')
	}

	// API latencies
	if len(bm.APILatencies) > 0 {
		b.WriteString("# HELP usulnet_api_request_duration_seconds Duration of API requests\n")
		b.WriteString("# TYPE usulnet_api_request_duration_seconds summary\n")
		for route, t := range bm.APILatencies {
			fmt.Fprintf(&b, "usulnet_api_request_duration_seconds_count{route=\"%s\"} %d\n",
				sanitizeLabel(route), t.count)
			fmt.Fprintf(&b, "usulnet_api_request_duration_seconds_sum{route=\"%s\"} %.6f\n",
				sanitizeLabel(route), t.sum)
		}
		b.WriteByte('\n')
	}

	return b.String()
}

// writeSimpleGauge writes a gauge with no labels.
func writeSimpleGauge(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s %.4f\n\n", name, value)
}

// CollectBusinessMetrics runs a periodic collection loop that gathers
// business metrics from various services. It should be called as a goroutine.
func CollectBusinessMetrics(ctx context.Context, bm *BusinessMetrics, log *logger.Logger) {
	log.Info("Business metrics collector started")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Business metrics collector stopped")
			return
		case <-ticker.C:
			// Business metrics are updated by the services themselves via
			// the RecordXxx methods. This loop serves as a heartbeat to
			// verify the collector is alive and can be extended with
			// pull-based collection if needed.
		}
	}
}
