// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metrics

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// FormatPrometheus renders all cached metrics in Prometheus text exposition format.
// This avoids a dependency on prometheus/client_golang — plain text generation
// is sufficient and keeps the binary small.
func FormatPrometheus(
	hosts map[uuid.UUID]*workers.HostMetrics,
	containers map[uuid.UUID][]*workers.ContainerMetrics,
) string {
	var b strings.Builder

	// Host metrics
	for _, h := range hosts {
		hostLabel := sanitizeLabel(h.HostID.String())

		writeGauge(&b, "usulnet_host_cpu_percent", "Current CPU usage percentage",
			h.CPUUsagePercent, "host", hostLabel)

		writeGaugeI64(&b, "usulnet_host_memory_used_bytes", "Memory used in bytes",
			h.MemoryUsed, "host", hostLabel)
		writeGaugeI64(&b, "usulnet_host_memory_total_bytes", "Total memory in bytes",
			h.MemoryTotal, "host", hostLabel)
		writeGauge(&b, "usulnet_host_memory_percent", "Memory usage percentage",
			h.MemoryPercent, "host", hostLabel)

		writeGaugeI64(&b, "usulnet_host_disk_used_bytes", "Disk used in bytes",
			h.DiskUsed, "host", hostLabel)
		writeGaugeI64(&b, "usulnet_host_disk_total_bytes", "Total disk in bytes",
			h.DiskTotal, "host", hostLabel)
		writeGauge(&b, "usulnet_host_disk_percent", "Disk usage percentage",
			h.DiskPercent, "host", hostLabel)

		writeGaugeI64(&b, "usulnet_host_network_rx_bytes", "Network received bytes",
			h.NetworkRxBytes, "host", hostLabel)
		writeGaugeI64(&b, "usulnet_host_network_tx_bytes", "Network transmitted bytes",
			h.NetworkTxBytes, "host", hostLabel)

		writeGaugeInt(&b, "usulnet_host_containers_total", "Total containers",
			h.ContainersTotal, "host", hostLabel)
		writeGaugeInt(&b, "usulnet_host_containers_running", "Running containers",
			h.ContainersRunning, "host", hostLabel)
		writeGaugeInt(&b, "usulnet_host_containers_stopped", "Stopped containers",
			h.ContainersStopped, "host", hostLabel)
		writeGaugeInt(&b, "usulnet_host_images_total", "Total images",
			h.ImagesTotal, "host", hostLabel)
		writeGaugeInt(&b, "usulnet_host_volumes_total", "Total volumes",
			h.VolumesTotal, "host", hostLabel)
	}

	// Container metrics
	for _, cms := range containers {
		for _, cm := range cms {
			name := sanitizeLabel(cm.ContainerName)
			id := cm.ContainerID
			if len(id) > 12 {
				id = id[:12]
			}

			labels := fmt.Sprintf(`name="%s",id="%s"`, name, id)

			writeGaugeLabels(&b, "usulnet_container_cpu_percent", "Container CPU usage",
				cm.CPUUsagePercent, labels)
			writeGaugeI64Labels(&b, "usulnet_container_memory_used_bytes", "Container memory used",
				cm.MemoryUsed, labels)
			writeGaugeI64Labels(&b, "usulnet_container_memory_limit_bytes", "Container memory limit",
				cm.MemoryLimit, labels)
			writeGaugeLabels(&b, "usulnet_container_memory_percent", "Container memory percentage",
				cm.MemoryPercent, labels)
			writeGaugeI64Labels(&b, "usulnet_container_network_rx_bytes", "Container network received",
				cm.NetworkRxBytes, labels)
			writeGaugeI64Labels(&b, "usulnet_container_network_tx_bytes", "Container network transmitted",
				cm.NetworkTxBytes, labels)
			writeGaugeI64Labels(&b, "usulnet_container_block_read_bytes", "Container block read",
				cm.BlockRead, labels)
			writeGaugeI64Labels(&b, "usulnet_container_block_write_bytes", "Container block write",
				cm.BlockWrite, labels)
			writeGaugeIntLabels(&b, "usulnet_container_pids", "Container PIDs",
				cm.PIDs, labels)

			// State as gauge (1=running, 0=other)
			stateVal := 0.0
			if cm.State == "running" {
				stateVal = 1.0
			}
			writeGaugeLabels(&b, "usulnet_container_running", "Container running state (1=running)",
				stateVal, labels)
		}
	}

	return b.String()
}

// ============================================================================
// Prometheus text format helpers
// ============================================================================

func writeGauge(b *strings.Builder, name, help string, value float64, labelKey, labelVal string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s=\"%s\"} %.4f\n\n", name, labelKey, labelVal, value)
}

func writeGaugeI64(b *strings.Builder, name, help string, value int64, labelKey, labelVal string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s=\"%s\"} %d\n\n", name, labelKey, labelVal, value)
}

func writeGaugeInt(b *strings.Builder, name, help string, value int, labelKey, labelVal string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s=\"%s\"} %d\n\n", name, labelKey, labelVal, value)
}

func writeGaugeLabels(b *strings.Builder, name, help string, value float64, labels string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s} %.4f\n\n", name, labels, value)
}

func writeGaugeI64Labels(b *strings.Builder, name, help string, value int64, labels string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s} %d\n\n", name, labels, value)
}

func writeGaugeIntLabels(b *strings.Builder, name, help string, value int, labels string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s{%s} %d\n\n", name, labels, value)
}

// sanitizeLabel cleans a value for use as a Prometheus label value.
func sanitizeLabel(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", "")
	return s
}
