// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dockerconfig manages the host's /etc/docker/daemon.json — the
// JSON configuration file consumed by dockerd. The package owns the full
// edit-validate-backup-write-reload-rollback cycle.
//
// v26.5.1 ports the v26.2.7 module under AGPL with three structural
// changes:
//
//  1. The 898-line monolithic service.go is split into reader.go,
//     writer.go and applier.go so each phase of the apply cycle is
//     independently testable.
//  2. Writes are atomic — temp file + fsync + rename — instead of the
//     v26.2.7 os.WriteFile path that could leave a partial JSON file on
//     disk after a crash.
//  3. The apply path verifies the daemon is healthy after reload with a
//     hard 60 s timeout. If the daemon does not return within that
//     window, or if its API is unhealthy, the previous daemon.json is
//     restored and a SIGHUP is re-issued — the rollback is forced.
//
// A separate audit notes:
//
//   - The v26.2.7 nsenter-via-docker-exec path (self-exec to read host
//     files) is intentionally not ported. Operators volume-mount
//     /etc/docker into the container as :rw instead. That removes a
//     fragile self-exec dependency, removes the need for the container
//     to run with --pid=host, and removes the docker-exec cycle that
//     would crash the editor when the daemon is down (the very state
//     the editor exists to fix).
//   - Registry-mirror credentials and proxy URLs containing user:pass
//     are redacted from logs and audit summaries; see redactURL in
//     applier.go and the credential-logging unit test.
package dockerconfig

import (
	"encoding/json"
	"time"
)

// RiskLevel indicates how dangerous a setting change is.
type RiskLevel string

// Risk levels surfaced to the UI to color-code daemon.json fields.
const (
	RiskSafe      RiskLevel = "safe"
	RiskModerate  RiskLevel = "moderate"
	RiskDangerous RiskLevel = "dangerous"
)

// ApplyMode indicates how to apply configuration changes.
type ApplyMode string

// Apply modes returned by the service after a successful write.
const (
	ApplyReload  ApplyMode = "reload"
	ApplyRestart ApplyMode = "restart"
)

// SettingMeta describes a daemon.json setting for the UI.
type SettingMeta struct {
	Key       string    `json:"key"`
	Label     string    `json:"label"`
	Help      string    `json:"help"`
	Category  string    `json:"category"`
	Risk      RiskLevel `json:"risk"`
	ApplyMode ApplyMode `json:"apply_mode"`
}

// DaemonConfig represents the full daemon.json structure.
//
// Pointer fields distinguish "not set" from zero values so the marshaled
// output is the minimal JSON the operator typed — usulnet never injects
// extra keys into a daemon.json that did not have them.
type DaemonConfig struct {
	// General
	Debug                  *bool    `json:"debug,omitempty"`
	Labels                 []string `json:"labels,omitempty"`
	ShutdownTimeout        *int     `json:"shutdown-timeout,omitempty"`
	MaxConcurrentDownloads *int     `json:"max-concurrent-downloads,omitempty"`
	MaxConcurrentUploads   *int     `json:"max-concurrent-uploads,omitempty"`
	MaxDownloadAttempts    *int     `json:"max-download-attempts,omitempty"`
	Experimental           *bool    `json:"experimental,omitempty"`
	MetricsAddr            *string  `json:"metrics-addr,omitempty"`

	// Network
	DefaultAddressPools []AddressPool `json:"default-address-pools,omitempty"`
	BIP                 *string       `json:"bip,omitempty"`
	FixedCIDR           *string       `json:"fixed-cidr,omitempty"`
	DefaultGateway      *string       `json:"default-gateway,omitempty"`
	DNS                 []string      `json:"dns,omitempty"`
	DNSSearch           []string      `json:"dns-search,omitempty"`
	DNSOpts             []string      `json:"dns-opts,omitempty"`
	MTU                 *int          `json:"mtu,omitempty"`
	ICC                 *bool         `json:"icc,omitempty"`
	IPv6                *bool         `json:"ipv6,omitempty"`
	IPForward           *bool         `json:"ip-forward,omitempty"`
	IPMasq              *bool         `json:"ip-masq,omitempty"`

	// Logging
	LogDriver *string           `json:"log-driver,omitempty"`
	LogOpts   map[string]string `json:"log-opts,omitempty"`
	LogLevel  *string           `json:"log-level,omitempty"`
	LogFormat *string           `json:"log-format,omitempty"`

	// Registry
	RegistryMirrors                []string `json:"registry-mirrors,omitempty"`
	InsecureRegistries             []string `json:"insecure-registries,omitempty"`
	AllowNondistributableArtifacts []string `json:"allow-nondistributable-artifacts,omitempty"`

	// Runtime
	DefaultRuntime      *string            `json:"default-runtime,omitempty"`
	Runtimes            map[string]Runtime `json:"runtimes,omitempty"`
	LiveRestore         *bool              `json:"live-restore,omitempty"`
	UserlandProxy       *bool              `json:"userland-proxy,omitempty"`
	Iptables            *bool              `json:"iptables,omitempty"`
	IP6Tables           *bool              `json:"ip6tables,omitempty"`
	Init                *bool              `json:"init,omitempty"`
	ExecOpts            []string           `json:"exec-opts,omitempty"`
	DefaultCgroupnsMode *string            `json:"default-cgroupns-mode,omitempty"`
	StorageDriver       *string            `json:"storage-driver,omitempty"`
	StorageOpts         []string           `json:"storage-opts,omitempty"`
	DataRoot            *string            `json:"data-root,omitempty"`

	// Proxy
	Proxies *ProxyConfig `json:"proxies,omitempty"`

	// Security
	DefaultUlimits       map[string]Ulimit `json:"default-ulimits,omitempty"`
	NoNewPrivileges      *bool             `json:"no-new-privileges,omitempty"`
	SeccompProfile       *string           `json:"seccomp-profile,omitempty"`
	SELinuxEnabled       *bool             `json:"selinux-enabled,omitempty"`
	UsernsRemap          *string           `json:"userns-remap,omitempty"`
	AuthorizationPlugins []string          `json:"authorization-plugins,omitempty"`

	// Catch-all for unknown fields the typed struct does not model.
	// Populated by UnmarshalJSON, re-emitted by MarshalJSON. This is
	// what keeps a hand-edited daemon.json round-trippable through
	// usulnet without losing operator-added keys.
	Extra map[string]json.RawMessage `json:"-"`
}

// AddressPool represents a Docker default address pool.
type AddressPool struct {
	Base string `json:"base"`
	Size int    `json:"size"`
}

// Runtime represents a registered OCI runtime.
type Runtime struct {
	Path string   `json:"path"`
	Args []string `json:"runtimeArgs,omitempty"`
}

// ProxyConfig holds Docker daemon proxy settings.
type ProxyConfig struct {
	HTTPProxy  *string `json:"http-proxy,omitempty"`
	HTTPSProxy *string `json:"https-proxy,omitempty"`
	NoProxy    *string `json:"no-proxy,omitempty"`
}

// Ulimit represents a resource limit.
type Ulimit struct {
	Name string `json:"Name"`
	Hard int64  `json:"Hard"`
	Soft int64  `json:"Soft"`
}

// Snapshot describes a daemon.json snapshot file (i.e. a historical
// backup). v26.2.7 called this BackupInfo; renamed for v26.5.1 because
// the API exposes it as "snapshot" and the backup verb is reserved for
// the application-level backup module.
type Snapshot struct {
	ID        string    `json:"id"`
	Path      string    `json:"-"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason,omitempty"`
}

// UpdateResult is returned after a successful Apply.
type UpdateResult struct {
	SnapshotID    string    `json:"snapshot_id,omitempty"`
	ApplyMode     ApplyMode `json:"apply_mode"`
	ChangedFields []string  `json:"changed_fields"`
	Reloaded      bool      `json:"reloaded"`
	RolledBack    bool      `json:"rolled_back"`
	RollbackError string    `json:"rollback_error,omitempty"`
	WarningMsg    string    `json:"warning,omitempty"`
}

// ValidationError describes a single validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Config holds service configuration.
type Config struct {
	// ConfigPath is the absolute path to daemon.json on disk.
	// Defaults to /etc/docker/daemon.json. The container deployment
	// must volume-mount the host's /etc/docker into this location with
	// rw access; usulnet does not shell out to nsenter.
	ConfigPath string

	// SnapshotDir is where atomic point-in-time backups of daemon.json
	// are written before each apply. Defaults to
	// /etc/docker/usulnet-snapshots. Must be on the same filesystem as
	// ConfigPath so rename() is atomic.
	SnapshotDir string

	// ReloadTimeout is the hard ceiling for waiting for dockerd to
	// settle after SIGHUP. If the daemon API is not healthy by this
	// deadline, the rollback path fires. Defaults to 60 s.
	ReloadTimeout time.Duration

	// ReloadPollInterval is how often the applier pings the daemon
	// after SIGHUP. Defaults to 1 s.
	ReloadPollInterval time.Duration

	// MaxSnapshots is the maximum number of historical snapshots to
	// retain. Older snapshots are pruned on each successful Apply.
	// Defaults to 50.
	MaxSnapshots int
}

// UnmarshalJSON implements custom unmarshaling to capture unknown fields.
func (d *DaemonConfig) UnmarshalJSON(data []byte) error {
	type alias DaemonConfig
	aux := &alias{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	*d = DaemonConfig(*aux)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// Already parsed the known fields above; if the second pass
		// fails the document is not a JSON object — treat extras as
		// absent rather than failing.
		return nil //nolint:nilerr
	}
	known := knownFields()
	d.Extra = make(map[string]json.RawMessage)
	for k, v := range raw {
		if !known[k] {
			d.Extra[k] = v
		}
	}
	return nil
}

// MarshalJSON implements custom marshaling to re-emit unknown fields.
func (d DaemonConfig) MarshalJSON() ([]byte, error) {
	type alias DaemonConfig
	data, err := json.Marshal(alias(d))
	if err != nil {
		return nil, err
	}
	if len(d.Extra) == 0 {
		return data, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	for k, v := range d.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.MarshalIndent(m, "", "  ")
}

// knownFields returns the set of JSON keys that DaemonConfig explicitly
// models. Used by UnmarshalJSON to route unrecognized keys into Extra
// so MarshalJSON can round-trip them.
func knownFields() map[string]bool {
	return map[string]bool{
		"debug": true, "labels": true, "shutdown-timeout": true,
		"max-concurrent-downloads": true, "max-concurrent-uploads": true,
		"max-download-attempts": true, "experimental": true, "metrics-addr": true,
		"default-address-pools": true, "bip": true, "fixed-cidr": true,
		"default-gateway": true, "dns": true, "dns-search": true, "dns-opts": true,
		"mtu": true, "icc": true, "ipv6": true, "ip-forward": true, "ip-masq": true,
		"log-driver": true, "log-opts": true, "log-level": true, "log-format": true,
		"registry-mirrors": true, "insecure-registries": true,
		"allow-nondistributable-artifacts": true,
		"default-runtime":                  true, "runtimes": true, "live-restore": true,
		"userland-proxy": true, "iptables": true, "ip6tables": true, "init": true,
		"exec-opts": true, "default-cgroupns-mode": true, "storage-driver": true,
		"storage-opts": true, "data-root": true,
		"proxies":         true,
		"default-ulimits": true, "no-new-privileges": true, "seccomp-profile": true,
		"selinux-enabled": true, "userns-remap": true, "authorization-plugins": true,
	}
}

// AllSettingsMeta returns metadata for all daemon.json settings — used
// by the editor UI to decorate fields with category/risk/apply-mode.
func AllSettingsMeta() map[string]SettingMeta {
	return map[string]SettingMeta{
		"debug":                    {Key: "debug", Label: "Debug Mode", Help: "Enable verbose debug logging", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"labels":                   {Key: "labels", Label: "Daemon Labels", Help: "Key-value metadata labels (key=value format)", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"shutdown-timeout":         {Key: "shutdown-timeout", Label: "Shutdown Timeout", Help: "Seconds to wait for containers to stop during daemon shutdown", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"max-concurrent-downloads": {Key: "max-concurrent-downloads", Label: "Max Concurrent Downloads", Help: "Max layer downloads per image pull (default: 3)", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"max-concurrent-uploads":   {Key: "max-concurrent-uploads", Label: "Max Concurrent Uploads", Help: "Max layer uploads per image push (default: 5)", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"max-download-attempts":    {Key: "max-download-attempts", Label: "Max Download Attempts", Help: "Retries for failed layer downloads (default: 5)", Category: "general", Risk: RiskSafe, ApplyMode: ApplyReload},
		"experimental":             {Key: "experimental", Label: "Experimental Features", Help: "Enable experimental daemon features", Category: "general", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"metrics-addr":             {Key: "metrics-addr", Label: "Metrics Address", Help: "Prometheus metrics endpoint (e.g., 127.0.0.1:9323)", Category: "general", Risk: RiskSafe, ApplyMode: ApplyRestart},

		"default-address-pools": {Key: "default-address-pools", Label: "Default Address Pools", Help: "IP pools for new networks (base CIDR + subnet size)", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"bip":                   {Key: "bip", Label: "Bridge IP (bip)", Help: "CIDR for the docker0 bridge (e.g., 192.168.1.1/24)", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"fixed-cidr":            {Key: "fixed-cidr", Label: "Fixed CIDR", Help: "Restrict container IPs to this subnet of the bridge", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"default-gateway":       {Key: "default-gateway", Label: "Default Gateway", Help: "Default gateway IP for the bridge network", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"dns":                   {Key: "dns", Label: "DNS Servers", Help: "DNS servers for all containers (one per line)", Category: "network", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"dns-search":            {Key: "dns-search", Label: "DNS Search Domains", Help: "Search domains appended to unqualified hostnames", Category: "network", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"dns-opts":              {Key: "dns-opts", Label: "DNS Options", Help: "Additional DNS resolver options (e.g., ndots:5)", Category: "network", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"mtu":                   {Key: "mtu", Label: "MTU", Help: "Maximum Transmission Unit for bridge (68-9000)", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"icc":                   {Key: "icc", Label: "Inter-Container Communication", Help: "Allow containers on default bridge to communicate", Category: "network", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"ipv6":                  {Key: "ipv6", Label: "IPv6", Help: "Enable IPv6 on the default bridge", Category: "network", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"ip-forward":            {Key: "ip-forward", Label: "IP Forward", Help: "Enable net.ipv4.ip_forward (required for networking)", Category: "network", Risk: RiskDangerous, ApplyMode: ApplyRestart},
		"ip-masq":               {Key: "ip-masq", Label: "IP Masquerade", Help: "Enable NAT for container internet access", Category: "network", Risk: RiskDangerous, ApplyMode: ApplyRestart},

		"log-driver": {Key: "log-driver", Label: "Default Log Driver", Help: "Logging driver for new containers", Category: "logging", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"log-opts":   {Key: "log-opts", Label: "Log Options", Help: "Driver-specific options (e.g., max-size, max-file)", Category: "logging", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"log-level":  {Key: "log-level", Label: "Daemon Log Level", Help: "Daemon verbosity: debug, info, warn, error, fatal", Category: "logging", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"log-format": {Key: "log-format", Label: "Daemon Log Format", Help: "Daemon log format: text or json", Category: "logging", Risk: RiskSafe, ApplyMode: ApplyRestart},

		"registry-mirrors":                 {Key: "registry-mirrors", Label: "Registry Mirrors", Help: "Docker Hub mirrors (one URL per line)", Category: "registry", Risk: RiskSafe, ApplyMode: ApplyReload},
		"insecure-registries":              {Key: "insecure-registries", Label: "Insecure Registries", Help: "Registries without TLS (one per line)", Category: "registry", Risk: RiskModerate, ApplyMode: ApplyReload},
		"allow-nondistributable-artifacts": {Key: "allow-nondistributable-artifacts", Label: "Non-Distributable Artifacts", Help: "Allow pushing foreign layers to these registries", Category: "registry", Risk: RiskSafe, ApplyMode: ApplyReload},

		"default-runtime":       {Key: "default-runtime", Label: "Default Runtime", Help: "Default OCI runtime (e.g., runc, nvidia)", Category: "runtime", Risk: RiskModerate, ApplyMode: ApplyReload},
		"runtimes":              {Key: "runtimes", Label: "Runtimes", Help: "Registered OCI runtimes (name -> binary path)", Category: "runtime", Risk: RiskSafe, ApplyMode: ApplyReload},
		"live-restore":          {Key: "live-restore", Label: "Live Restore", Help: "Keep containers running during daemon downtime", Category: "runtime", Risk: RiskSafe, ApplyMode: ApplyReload},
		"userland-proxy":        {Key: "userland-proxy", Label: "Userland Proxy", Help: "Use docker-proxy for port forwarding (vs iptables)", Category: "runtime", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"iptables":              {Key: "iptables", Label: "iptables", Help: "Allow Docker to manage iptables rules", Category: "runtime", Risk: RiskDangerous, ApplyMode: ApplyRestart},
		"ip6tables":             {Key: "ip6tables", Label: "ip6tables", Help: "Allow Docker to manage IPv6 ip6tables rules", Category: "runtime", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"init":                  {Key: "init", Label: "Init Process", Help: "Run tini init in all containers for signal handling", Category: "runtime", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"exec-opts":             {Key: "exec-opts", Label: "Exec Options", Help: "Runtime exec options (e.g., native.cgroupdriver=systemd)", Category: "runtime", Risk: RiskDangerous, ApplyMode: ApplyRestart},
		"default-cgroupns-mode": {Key: "default-cgroupns-mode", Label: "Default Cgroup NS Mode", Help: "Container cgroup namespace: private or host", Category: "runtime", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"storage-driver":        {Key: "storage-driver", Label: "Storage Driver", Help: "Image/container storage driver (changing loses data!)", Category: "runtime", Risk: RiskDangerous, ApplyMode: ApplyRestart},
		"storage-opts":          {Key: "storage-opts", Label: "Storage Options", Help: "Driver-specific options (e.g., overlay2.size=20G)", Category: "runtime", Risk: RiskDangerous, ApplyMode: ApplyRestart},
		"data-root":             {Key: "data-root", Label: "Data Root", Help: "Docker data directory (default: /var/lib/docker)", Category: "runtime", Risk: RiskDangerous, ApplyMode: ApplyRestart},

		"proxies.http-proxy":  {Key: "proxies.http-proxy", Label: "HTTP Proxy", Help: "HTTP proxy for daemon (image pulls)", Category: "proxy", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"proxies.https-proxy": {Key: "proxies.https-proxy", Label: "HTTPS Proxy", Help: "HTTPS proxy for daemon", Category: "proxy", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"proxies.no-proxy":    {Key: "proxies.no-proxy", Label: "No Proxy", Help: "Hosts/CIDRs that bypass proxy (comma-separated)", Category: "proxy", Risk: RiskSafe, ApplyMode: ApplyRestart},

		"default-ulimits":       {Key: "default-ulimits", Label: "Default Ulimits", Help: "Default resource limits for containers", Category: "security", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"no-new-privileges":     {Key: "no-new-privileges", Label: "No New Privileges", Help: "Prevent processes from gaining privileges via setuid", Category: "security", Risk: RiskSafe, ApplyMode: ApplyRestart},
		"seccomp-profile":       {Key: "seccomp-profile", Label: "Seccomp Profile", Help: "Path to custom seccomp profile JSON", Category: "security", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"selinux-enabled":       {Key: "selinux-enabled", Label: "SELinux", Help: "Enable SELinux support for containers", Category: "security", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"userns-remap":          {Key: "userns-remap", Label: "User Namespace Remap", Help: "Remap container UIDs (e.g., 'default' or 'user:group')", Category: "security", Risk: RiskModerate, ApplyMode: ApplyRestart},
		"authorization-plugins": {Key: "authorization-plugins", Label: "Authorization Plugins", Help: "Docker API authorization plugins", Category: "security", Risk: RiskModerate, ApplyMode: ApplyReload},
	}
}
