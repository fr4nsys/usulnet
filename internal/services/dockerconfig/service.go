// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dockerconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Service manages the host's Docker daemon configuration (daemon.json).
//
// One Service per host. The struct holds no per-request state — the
// only mutable field is mu, which serializes Apply / Restore / snapshot
// so that concurrent operators in the web UI cannot interleave half a
// daemon.json onto disk. Read calls are not gated by mu so the editor
// page never blocks while another operator is mid-apply.
type Service struct {
	logger *logger.Logger
	cfg    Config
	health HealthChecker

	mu sync.Mutex
}

// NewService creates a new Docker config service.
//
// Config zero-fields are filled with defaults so callers can pass
// Config{} for the standard /etc/docker setup. The HealthChecker is
// optional; pass docker.Client (or any *Client wrapper that implements
// Ping) so the apply path can verify dockerd after SIGHUP. With a nil
// checker the apply path writes the file but skips the reload step
// rather than reporting a false-positive success.
func NewService(cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = "/etc/docker/daemon.json"
	}
	if cfg.SnapshotDir == "" {
		cfg.SnapshotDir = "/etc/docker/usulnet-snapshots"
	}
	if cfg.ReloadTimeout <= 0 {
		cfg.ReloadTimeout = 60 * time.Second
	}
	if cfg.ReloadPollInterval <= 0 {
		cfg.ReloadPollInterval = time.Second
	}
	if cfg.MaxSnapshots <= 0 {
		cfg.MaxSnapshots = 50
	}
	return &Service{
		logger: log.Named("dockerconfig"),
		cfg:    cfg,
	}
}

// SetHealthChecker wires the docker daemon health probe used to verify
// dockerd is alive after SIGHUP. Called after Docker client init in
// app boot. Safe to call before Apply but must not be called from
// inside an in-flight Apply.
func (s *Service) SetHealthChecker(h HealthChecker) {
	s.health = h
}

// ConfigPath returns the configured daemon.json path. Used by the web
// handler to display the path on the editor page.
func (s *Service) ConfigPath() string {
	return s.cfg.ConfigPath
}

// ReloadTimeout returns the configured hard reload timeout — surfaced
// in the UI so the operator knows how long an apply may stall.
func (s *Service) ReloadTimeout() time.Duration {
	return s.cfg.ReloadTimeout
}

// ====================================================================
// JSON helpers used by reader / writer / applier.
// ====================================================================

// unmarshalStrict parses raw bytes into v. Unlike json.Unmarshal it
// rejects fields that are present-but-malformed (e.g. an integer where
// a bool is expected) the same way dockerd would. Empty input is OK
// and leaves v at its zero value.
func unmarshalStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// marshalIndent emits the canonical 2-space-indented daemon.json text.
// Used by the apply path to normalise on-disk bytes so snapshot diffs
// stay clean.
func marshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// diffFields returns the set of daemon.json keys that differ between
// old and new. Order is deterministic (alphabetical) so the audit log
// and UI render stable summaries.
//
// The diff is field-name-only — we never include values, both because
// values can be huge (an authorization-plugins list) and because some
// values carry credentials.
func diffFields(oldCfg, newCfg *DaemonConfig) []string {
	if oldCfg == nil {
		oldCfg = &DaemonConfig{}
	}
	if newCfg == nil {
		newCfg = &DaemonConfig{}
	}

	oldM := flatten(oldCfg)
	newM := flatten(newCfg)

	keys := make(map[string]bool, len(oldM)+len(newM))
	for k := range oldM {
		keys[k] = true
	}
	for k := range newM {
		keys[k] = true
	}

	var changed []string
	for k := range keys {
		if !reflect.DeepEqual(oldM[k], newM[k]) {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	return changed
}

// flatten converts DaemonConfig into a key→value map keyed by the
// dotted setting names used in AllSettingsMeta. Used by diffFields.
func flatten(cfg *DaemonConfig) map[string]any {
	out := map[string]any{}
	if cfg.Debug != nil {
		out["debug"] = *cfg.Debug
	}
	if len(cfg.Labels) > 0 {
		out["labels"] = cfg.Labels
	}
	if cfg.ShutdownTimeout != nil {
		out["shutdown-timeout"] = *cfg.ShutdownTimeout
	}
	if cfg.MaxConcurrentDownloads != nil {
		out["max-concurrent-downloads"] = *cfg.MaxConcurrentDownloads
	}
	if cfg.MaxConcurrentUploads != nil {
		out["max-concurrent-uploads"] = *cfg.MaxConcurrentUploads
	}
	if cfg.MaxDownloadAttempts != nil {
		out["max-download-attempts"] = *cfg.MaxDownloadAttempts
	}
	if cfg.Experimental != nil {
		out["experimental"] = *cfg.Experimental
	}
	if cfg.MetricsAddr != nil {
		out["metrics-addr"] = *cfg.MetricsAddr
	}
	if len(cfg.DefaultAddressPools) > 0 {
		out["default-address-pools"] = cfg.DefaultAddressPools
	}
	if cfg.BIP != nil {
		out["bip"] = *cfg.BIP
	}
	if cfg.FixedCIDR != nil {
		out["fixed-cidr"] = *cfg.FixedCIDR
	}
	if cfg.DefaultGateway != nil {
		out["default-gateway"] = *cfg.DefaultGateway
	}
	if len(cfg.DNS) > 0 {
		out["dns"] = cfg.DNS
	}
	if len(cfg.DNSSearch) > 0 {
		out["dns-search"] = cfg.DNSSearch
	}
	if len(cfg.DNSOpts) > 0 {
		out["dns-opts"] = cfg.DNSOpts
	}
	if cfg.MTU != nil {
		out["mtu"] = *cfg.MTU
	}
	if cfg.ICC != nil {
		out["icc"] = *cfg.ICC
	}
	if cfg.IPv6 != nil {
		out["ipv6"] = *cfg.IPv6
	}
	if cfg.IPForward != nil {
		out["ip-forward"] = *cfg.IPForward
	}
	if cfg.IPMasq != nil {
		out["ip-masq"] = *cfg.IPMasq
	}
	if cfg.LogDriver != nil {
		out["log-driver"] = *cfg.LogDriver
	}
	if len(cfg.LogOpts) > 0 {
		out["log-opts"] = cfg.LogOpts
	}
	if cfg.LogLevel != nil {
		out["log-level"] = *cfg.LogLevel
	}
	if cfg.LogFormat != nil {
		out["log-format"] = *cfg.LogFormat
	}
	if len(cfg.RegistryMirrors) > 0 {
		out["registry-mirrors"] = cfg.RegistryMirrors
	}
	if len(cfg.InsecureRegistries) > 0 {
		out["insecure-registries"] = cfg.InsecureRegistries
	}
	if len(cfg.AllowNondistributableArtifacts) > 0 {
		out["allow-nondistributable-artifacts"] = cfg.AllowNondistributableArtifacts
	}
	if cfg.DefaultRuntime != nil {
		out["default-runtime"] = *cfg.DefaultRuntime
	}
	if len(cfg.Runtimes) > 0 {
		out["runtimes"] = cfg.Runtimes
	}
	if cfg.LiveRestore != nil {
		out["live-restore"] = *cfg.LiveRestore
	}
	if cfg.UserlandProxy != nil {
		out["userland-proxy"] = *cfg.UserlandProxy
	}
	if cfg.Iptables != nil {
		out["iptables"] = *cfg.Iptables
	}
	if cfg.IP6Tables != nil {
		out["ip6tables"] = *cfg.IP6Tables
	}
	if cfg.Init != nil {
		out["init"] = *cfg.Init
	}
	if len(cfg.ExecOpts) > 0 {
		out["exec-opts"] = cfg.ExecOpts
	}
	if cfg.DefaultCgroupnsMode != nil {
		out["default-cgroupns-mode"] = *cfg.DefaultCgroupnsMode
	}
	if cfg.StorageDriver != nil {
		out["storage-driver"] = *cfg.StorageDriver
	}
	if len(cfg.StorageOpts) > 0 {
		out["storage-opts"] = cfg.StorageOpts
	}
	if cfg.DataRoot != nil {
		out["data-root"] = *cfg.DataRoot
	}
	if cfg.Proxies != nil {
		if cfg.Proxies.HTTPProxy != nil {
			out["proxies.http-proxy"] = *cfg.Proxies.HTTPProxy
		}
		if cfg.Proxies.HTTPSProxy != nil {
			out["proxies.https-proxy"] = *cfg.Proxies.HTTPSProxy
		}
		if cfg.Proxies.NoProxy != nil {
			out["proxies.no-proxy"] = *cfg.Proxies.NoProxy
		}
	}
	if len(cfg.DefaultUlimits) > 0 {
		out["default-ulimits"] = cfg.DefaultUlimits
	}
	if cfg.NoNewPrivileges != nil {
		out["no-new-privileges"] = *cfg.NoNewPrivileges
	}
	if cfg.SeccompProfile != nil {
		out["seccomp-profile"] = *cfg.SeccompProfile
	}
	if cfg.SELinuxEnabled != nil {
		out["selinux-enabled"] = *cfg.SELinuxEnabled
	}
	if cfg.UsernsRemap != nil {
		out["userns-remap"] = *cfg.UsernsRemap
	}
	if len(cfg.AuthorizationPlugins) > 0 {
		out["authorization-plugins"] = cfg.AuthorizationPlugins
	}
	return out
}
