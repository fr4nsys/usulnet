// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ComposeFile represents a parsed docker-compose.yml file
type ComposeFile struct {
	Version  string                    `yaml:"version,omitempty"`
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]ComposeNetwork `yaml:"networks,omitempty"`
	Volumes  map[string]ComposeVolume  `yaml:"volumes,omitempty"`
	Secrets  map[string]ComposeSecret  `yaml:"secrets,omitempty"`
	Configs  map[string]ComposeConfig  `yaml:"configs,omitempty"`
}

// ComposeService represents a service in docker-compose
type ComposeService struct {
	Image         string            `yaml:"image,omitempty"`
	Build         *ComposeBuild     `yaml:"build,omitempty"`
	ContainerName string            `yaml:"container_name,omitempty"`
	Command       interface{}       `yaml:"command,omitempty"`       // string or []string
	Entrypoint    interface{}       `yaml:"entrypoint,omitempty"`    // string or []string
	Environment   interface{}       `yaml:"environment,omitempty"`   // map or list
	EnvFile       interface{}       `yaml:"env_file,omitempty"`      // string or []string
	Ports         []string          `yaml:"ports,omitempty"`
	Volumes       []string          `yaml:"volumes,omitempty"`
	Networks      interface{}       `yaml:"networks,omitempty"`      // []string or map
	DependsOn     interface{}       `yaml:"depends_on,omitempty"`    // []string or map
	Labels        map[string]string `yaml:"labels,omitempty"`
	Restart       string            `yaml:"restart,omitempty"`
	HealthCheck   *ComposeHealth    `yaml:"healthcheck,omitempty"`
	Deploy        *ComposeDeploy    `yaml:"deploy,omitempty"`
	User          string            `yaml:"user,omitempty"`
	WorkingDir    string            `yaml:"working_dir,omitempty"`
	Hostname      string            `yaml:"hostname,omitempty"`
	Domainname    string            `yaml:"domainname,omitempty"`
	Privileged    bool              `yaml:"privileged,omitempty"`
	StdinOpen     bool              `yaml:"stdin_open,omitempty"`
	Tty           bool              `yaml:"tty,omitempty"`
	DNS           interface{}       `yaml:"dns,omitempty"`           // string or []string
	DNSSearch     interface{}       `yaml:"dns_search,omitempty"`    // string or []string
	ExtraHosts    []string          `yaml:"extra_hosts,omitempty"`
	CapAdd        []string          `yaml:"cap_add,omitempty"`
	CapDrop       []string          `yaml:"cap_drop,omitempty"`
	Devices       []string          `yaml:"devices,omitempty"`
	SecurityOpt   []string          `yaml:"security_opt,omitempty"`
	Sysctls       map[string]string `yaml:"sysctls,omitempty"`
	Ulimits       map[string]interface{} `yaml:"ulimits,omitempty"`
	Logging       *ComposeLogging   `yaml:"logging,omitempty"`
	StopSignal    string            `yaml:"stop_signal,omitempty"`
	StopGracePeriod string          `yaml:"stop_grace_period,omitempty"`
}

// ComposeBuild represents build configuration
type ComposeBuild struct {
	Context    string            `yaml:"context,omitempty"`
	Dockerfile string            `yaml:"dockerfile,omitempty"`
	Args       map[string]string `yaml:"args,omitempty"`
	Target     string            `yaml:"target,omitempty"`
	CacheFrom  []string          `yaml:"cache_from,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty"`
	Network    string            `yaml:"network,omitempty"`
}

// ComposeHealth represents healthcheck configuration
type ComposeHealth struct {
	Test        interface{} `yaml:"test,omitempty"` // string or []string
	Interval    string      `yaml:"interval,omitempty"`
	Timeout     string      `yaml:"timeout,omitempty"`
	Retries     int         `yaml:"retries,omitempty"`
	StartPeriod string      `yaml:"start_period,omitempty"`
	Disable     bool        `yaml:"disable,omitempty"`
}

// ComposeDeploy represents deploy configuration
type ComposeDeploy struct {
	Replicas      int                `yaml:"replicas,omitempty"`
	Resources     *ComposeResources  `yaml:"resources,omitempty"`
	RestartPolicy *ComposeRestart    `yaml:"restart_policy,omitempty"`
	Labels        map[string]string  `yaml:"labels,omitempty"`
	Mode          string             `yaml:"mode,omitempty"`
}

// ComposeResources represents resource limits
type ComposeResources struct {
	Limits       *ComposeResourceSpec `yaml:"limits,omitempty"`
	Reservations *ComposeResourceSpec `yaml:"reservations,omitempty"`
}

// ComposeResourceSpec represents specific resource values
type ComposeResourceSpec struct {
	CPUs   string `yaml:"cpus,omitempty"`
	Memory string `yaml:"memory,omitempty"`
}

// ComposeRestart represents restart policy
type ComposeRestart struct {
	Condition   string `yaml:"condition,omitempty"`
	Delay       string `yaml:"delay,omitempty"`
	MaxAttempts int    `yaml:"max_attempts,omitempty"`
	Window      string `yaml:"window,omitempty"`
}

// ComposeNetwork represents a network definition
type ComposeNetwork struct {
	Driver     string            `yaml:"driver,omitempty"`
	DriverOpts map[string]string `yaml:"driver_opts,omitempty"`
	External   interface{}       `yaml:"external,omitempty"` // bool or map with name
	Internal   bool              `yaml:"internal,omitempty"`
	Attachable bool              `yaml:"attachable,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty"`
	IPAM       *ComposeIPAM      `yaml:"ipam,omitempty"`
	Name       string            `yaml:"name,omitempty"`
}

// ComposeIPAM represents IPAM configuration
type ComposeIPAM struct {
	Driver string            `yaml:"driver,omitempty"`
	Config []ComposeIPAMPool `yaml:"config,omitempty"`
}

// ComposeIPAMPool represents IPAM pool configuration
type ComposeIPAMPool struct {
	Subnet  string `yaml:"subnet,omitempty"`
	Gateway string `yaml:"gateway,omitempty"`
}

// ComposeVolume represents a volume definition
type ComposeVolume struct {
	Driver     string            `yaml:"driver,omitempty"`
	DriverOpts map[string]string `yaml:"driver_opts,omitempty"`
	External   interface{}       `yaml:"external,omitempty"` // bool or map with name
	Labels     map[string]string `yaml:"labels,omitempty"`
	Name       string            `yaml:"name,omitempty"`
}

// ComposeSecret represents a secret definition
type ComposeSecret struct {
	File     string `yaml:"file,omitempty"`
	External bool   `yaml:"external,omitempty"`
	Name     string `yaml:"name,omitempty"`
}

// ComposeConfig represents a config definition
type ComposeConfig struct {
	File     string `yaml:"file,omitempty"`
	External bool   `yaml:"external,omitempty"`
	Name     string `yaml:"name,omitempty"`
}

// ComposeLogging represents logging configuration
type ComposeLogging struct {
	Driver  string            `yaml:"driver,omitempty"`
	Options map[string]string `yaml:"options,omitempty"`
}

// Stack represents a deployed compose stack
type Stack struct {
	Name       string
	ProjectDir string
	Services   []string
	Networks   []string
	Volumes    []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// StackStatus represents the status of a stack
type StackStatus struct {
	Name     string
	Running  int
	Stopped  int
	Exited   int
	Services []ServiceStatus
}

// ServiceStatus represents the status of a service within a stack
type ServiceStatus struct {
	Name       string
	Replicas   int
	Running    int
	Image      string
	Ports      []string
	Status     string
}

// ParseComposeFile parses a docker-compose.yml file
func ParseComposeFile(data []byte) (*ComposeFile, error) {
	var compose ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeInvalid, "failed to parse compose file")
	}

	if len(compose.Services) == 0 {
		return nil, errors.New(errors.CodeComposeInvalid, "compose file has no services defined")
	}

	return &compose, nil
}

// ParseComposeFileFromPath parses a docker-compose.yml file from a path
func ParseComposeFileFromPath(path string) (*ComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeInvalid, "failed to read compose file")
	}

	return ParseComposeFile(data)
}

// Validate validates the compose file structure
func (c *ComposeFile) Validate() error {
	for name, service := range c.Services {
		if service.Image == "" && service.Build == nil {
			return errors.New(errors.CodeComposeInvalid,
				fmt.Sprintf("service '%s' must have either 'image' or 'build' defined", name))
		}
	}
	return nil
}

// GetServiceNames returns a list of all service names
func (c *ComposeFile) GetServiceNames() []string {
	names := make([]string, 0, len(c.Services))
	for name := range c.Services {
		names = append(names, name)
	}
	return names
}

// GetNetworkNames returns a list of all network names
func (c *ComposeFile) GetNetworkNames() []string {
	names := make([]string, 0, len(c.Networks))
	for name := range c.Networks {
		names = append(names, name)
	}
	return names
}

// GetVolumeNames returns a list of all volume names
func (c *ComposeFile) GetVolumeNames() []string {
	names := make([]string, 0, len(c.Volumes))
	for name := range c.Volumes {
		names = append(names, name)
	}
	return names
}

// ComposeDeployOptions specifies options for deploying a compose stack
type ComposeDeployOptions struct {
	// ProjectName is the stack/project name
	ProjectName string

	// ProjectDir is the directory containing the compose file
	ProjectDir string

	// ComposeFiles are the compose file paths (can be multiple for overrides)
	ComposeFiles []string

	// Environment variables to pass to compose
	Environment map[string]string

	// Build forces build of images before starting
	Build bool

	// ForceRecreate forces recreation of containers
	ForceRecreate bool

	// NoDeps doesn't start linked services
	NoDeps bool

	// Detach runs in background
	Detach bool

	// RemoveOrphans removes containers for services not defined in compose
	RemoveOrphans bool

	// Timeout for container startup
	Timeout time.Duration

	// Scale specifies the number of replicas per service
	Scale map[string]int
}

// ComposeManager handles docker-compose operations
type ComposeManager struct {
	client          *Client
	composeBinary   string
	defaultTimeout  time.Duration
}

// NewComposeManager creates a new compose manager
func NewComposeManager(client *Client) *ComposeManager {
	// Try to find docker compose (v2) or docker-compose (v1)
	binary := findComposeBinary()

	return &ComposeManager{
		client:         client,
		composeBinary:  binary,
		defaultTimeout: 5 * time.Minute,
	}
}

// findComposeBinary locates the docker compose binary
func findComposeBinary() string {
	// Try docker compose (v2) first
	if _, err := exec.LookPath("docker"); err == nil {
		// Check if docker compose subcommand exists
		cmd := exec.Command("docker", "compose", "version")
		if err := cmd.Run(); err == nil {
			return "docker compose"
		}
	}

	// Fall back to docker-compose (v1)
	if path, err := exec.LookPath("docker-compose"); err == nil {
		return path
	}

	return ""
}

// IsAvailable checks if docker compose is available
func (m *ComposeManager) IsAvailable() bool {
	return m.composeBinary != ""
}

// Deploy deploys a compose stack
func (m *ComposeManager) Deploy(ctx context.Context, opts ComposeDeployOptions) error {
	log := logger.FromContext(ctx)

	if !m.IsAvailable() {
		return errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	if len(opts.ComposeFiles) == 0 {
		return errors.New(errors.CodeComposeInvalid, "no compose files specified")
	}

	// Build command arguments
	args := m.buildComposeArgs(opts)
	args = append(args, "up")

	if opts.Detach {
		args = append(args, "-d")
	}
	if opts.Build {
		args = append(args, "--build")
	}
	if opts.ForceRecreate {
		args = append(args, "--force-recreate")
	}
	if opts.NoDeps {
		args = append(args, "--no-deps")
	}
	if opts.RemoveOrphans {
		args = append(args, "--remove-orphans")
	}

	// Add scale options
	for service, replicas := range opts.Scale {
		args = append(args, "--scale", fmt.Sprintf("%s=%d", service, replicas))
	}

	log.Info("Deploying compose stack",
		"project", opts.ProjectName,
		"files", opts.ComposeFiles,
	)

	// Execute command
	output, err := m.runComposeCommand(ctx, opts.ProjectDir, opts.Environment, args...)
	if err != nil {
		log.Error("Failed to deploy compose stack",
			"project", opts.ProjectName,
			"error", err,
			"output", output,
		)
		return errors.Wrap(err, errors.CodeComposeFailed, "failed to deploy stack")
	}

	log.Info("Compose stack deployed successfully", "project", opts.ProjectName)
	return nil
}

// Stop stops a compose stack
func (m *ComposeManager) Stop(ctx context.Context, projectName, projectDir string, composeFiles []string, timeout time.Duration) error {
	log := logger.FromContext(ctx)

	if !m.IsAvailable() {
		return errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "stop")

	if timeout > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", int(timeout.Seconds())))
	}

	log.Info("Stopping compose stack", "project", projectName)

	output, err := m.runComposeCommand(ctx, projectDir, nil, args...)
	if err != nil {
		log.Error("Failed to stop compose stack",
			"project", projectName,
			"error", err,
			"output", output,
		)
		return errors.Wrap(err, errors.CodeComposeFailed, "failed to stop stack")
	}

	return nil
}

// Down removes a compose stack
func (m *ComposeManager) Down(ctx context.Context, projectName, projectDir string, composeFiles []string, removeVolumes, removeOrphans bool) error {
	log := logger.FromContext(ctx)

	if !m.IsAvailable() {
		return errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "down")

	if removeVolumes {
		args = append(args, "-v")
	}
	if removeOrphans {
		args = append(args, "--remove-orphans")
	}

	log.Info("Removing compose stack", "project", projectName)

	output, err := m.runComposeCommand(ctx, projectDir, nil, args...)
	if err != nil {
		log.Error("Failed to remove compose stack",
			"project", projectName,
			"error", err,
			"output", output,
		)
		return errors.Wrap(err, errors.CodeComposeFailed, "failed to remove stack")
	}

	return nil
}

// Restart restarts a compose stack
func (m *ComposeManager) Restart(ctx context.Context, projectName, projectDir string, composeFiles []string, timeout time.Duration) error {
	log := logger.FromContext(ctx)

	if !m.IsAvailable() {
		return errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "restart")

	if timeout > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", int(timeout.Seconds())))
	}

	log.Info("Restarting compose stack", "project", projectName)

	output, err := m.runComposeCommand(ctx, projectDir, nil, args...)
	if err != nil {
		log.Error("Failed to restart compose stack",
			"project", projectName,
			"error", err,
			"output", output,
		)
		return errors.Wrap(err, errors.CodeComposeFailed, "failed to restart stack")
	}

	return nil
}

// Pull pulls images for a compose stack
func (m *ComposeManager) Pull(ctx context.Context, projectName, projectDir string, composeFiles []string, services []string) error {
	log := logger.FromContext(ctx)

	if !m.IsAvailable() {
		return errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "pull")
	args = append(args, services...)

	log.Info("Pulling compose images", "project", projectName, "services", services)

	output, err := m.runComposeCommand(ctx, projectDir, nil, args...)
	if err != nil {
		log.Error("Failed to pull compose images",
			"project", projectName,
			"error", err,
			"output", output,
		)
		return errors.Wrap(err, errors.CodeComposeFailed, "failed to pull images")
	}

	return nil
}

// Logs returns logs for a compose stack
func (m *ComposeManager) Logs(ctx context.Context, projectName, projectDir string, composeFiles []string, services []string, follow bool, tail string) (io.ReadCloser, error) {
	if !m.IsAvailable() {
		return nil, errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "logs")

	if follow {
		args = append(args, "-f")
	}
	if tail != "" {
		args = append(args, "--tail", tail)
	}
	args = append(args, services...)

	cmd := m.buildCommand(ctx, projectDir, nil, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeFailed, "failed to create stdout pipe")
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeFailed, "failed to start logs command")
	}

	return &composeLogReader{
		reader: stdout,
		cmd:    cmd,
	}, nil
}

// composeLogReader wraps the log output
type composeLogReader struct {
	reader io.ReadCloser
	cmd    *exec.Cmd
}

func (r *composeLogReader) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

func (r *composeLogReader) Close() error {
	r.reader.Close()
	return r.cmd.Process.Kill()
}

// Ps returns the status of services in a compose stack
func (m *ComposeManager) Ps(ctx context.Context, projectName, projectDir string, composeFiles []string) ([]ServiceStatus, error) {
	if !m.IsAvailable() {
		return nil, errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ProjectName:  projectName,
		ComposeFiles: composeFiles,
	})
	args = append(args, "ps", "--format", "json")

	output, err := m.runComposeCommand(ctx, projectDir, nil, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeFailed, "failed to get stack status")
	}

	// Parse JSON output (docker compose v2 outputs JSON with --format json)
	// For simplicity, we'll parse the text output and return basic status
	// A full implementation would parse the JSON properly
	var services []ServiceStatus

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Basic parsing - real implementation would use JSON
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			services = append(services, ServiceStatus{
				Name:   parts[0],
				Status: parts[len(parts)-1],
			})
		}
	}

	return services, nil
}

// Config validates and displays the resolved compose configuration
func (m *ComposeManager) Config(ctx context.Context, projectDir string, composeFiles []string) (string, error) {
	if !m.IsAvailable() {
		return "", errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	args := m.buildComposeArgs(ComposeDeployOptions{
		ComposeFiles: composeFiles,
	})
	args = append(args, "config")

	return m.runComposeCommand(ctx, projectDir, nil, args...)
}

// buildComposeArgs builds common compose command arguments
func (m *ComposeManager) buildComposeArgs(opts ComposeDeployOptions) []string {
	var args []string

	// Handle docker compose vs docker-compose
	if m.composeBinary == "docker compose" {
		args = append(args, "compose")
	}

	if opts.ProjectName != "" {
		args = append(args, "-p", opts.ProjectName)
	}

	for _, f := range opts.ComposeFiles {
		args = append(args, "-f", f)
	}

	return args
}

// buildCommand builds an exec.Cmd for compose operations
func (m *ComposeManager) buildCommand(ctx context.Context, projectDir string, env map[string]string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd

	if m.composeBinary == "docker compose" {
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		// Remove "compose" from args if present (for docker-compose binary)
		if len(args) > 0 && args[0] == "compose" {
			args = args[1:]
		}
		cmd = exec.CommandContext(ctx, m.composeBinary, args...)
	}

	if projectDir != "" {
		cmd.Dir = projectDir
	}

	// Set environment
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	return cmd
}

// runComposeCommand executes a compose command and returns the output
func (m *ComposeManager) runComposeCommand(ctx context.Context, projectDir string, env map[string]string, args ...string) (string, error) {
	cmd := m.buildCommand(ctx, projectDir, env, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += stderr.String()
	}

	return output, err
}

// ListStacks returns a list of running compose stacks
func (m *ComposeManager) ListStacks(ctx context.Context) ([]Stack, error) {
	if !m.IsAvailable() {
		return nil, errors.New(errors.CodeComposeFailed, "docker compose is not available")
	}

	// Use docker compose ls to list projects
	args := []string{"compose", "ls", "--format", "json"}
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeComposeFailed, "failed to list stacks")
	}

	// Parse output (simplified - real implementation would parse JSON)
	var stacks []Stack
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			stacks = append(stacks, Stack{
				Name: parts[0],
			})
		}
	}

	return stacks, nil
}

// GetStackContainers returns containers belonging to a stack
func (m *ComposeManager) GetStackContainers(ctx context.Context, projectName string) ([]Container, error) {
	// Use Docker API to list containers with project label
	return m.client.ContainerList(ctx, ContainerListOptions{
		All: true,
		Filters: map[string][]string{
			"label": {fmt.Sprintf("com.docker.compose.project=%s", projectName)},
		},
	})
}

// SaveComposeFile saves a compose file to disk
func SaveComposeFile(compose *ComposeFile, path string) error {
	data, err := yaml.Marshal(compose)
	if err != nil {
		return errors.Wrap(err, errors.CodeComposeInvalid, "failed to marshal compose file")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create directory")
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to write compose file")
	}

	return nil
}

// MergeComposeFiles merges multiple compose files (override pattern)
func MergeComposeFiles(base *ComposeFile, override *ComposeFile) *ComposeFile {
	result := &ComposeFile{
		Version:  base.Version,
		Services: make(map[string]ComposeService),
		Networks: make(map[string]ComposeNetwork),
		Volumes:  make(map[string]ComposeVolume),
	}

	// Copy base services
	for name, svc := range base.Services {
		result.Services[name] = svc
	}

	// Override with new services
	for name, svc := range override.Services {
		if existing, ok := result.Services[name]; ok {
			// Merge existing service with override
			result.Services[name] = mergeService(existing, svc)
		} else {
			result.Services[name] = svc
		}
	}

	// Copy base networks
	for name, net := range base.Networks {
		result.Networks[name] = net
	}
	// Override networks
	for name, net := range override.Networks {
		result.Networks[name] = net
	}

	// Copy base volumes
	for name, vol := range base.Volumes {
		result.Volumes[name] = vol
	}
	// Override volumes
	for name, vol := range override.Volumes {
		result.Volumes[name] = vol
	}

	return result
}

// mergeService merges two service configurations
func mergeService(base, override ComposeService) ComposeService {
	result := base

	if override.Image != "" {
		result.Image = override.Image
	}
	if override.ContainerName != "" {
		result.ContainerName = override.ContainerName
	}
	if override.Command != nil {
		result.Command = override.Command
	}
	if override.Environment != nil {
		result.Environment = override.Environment
	}
	if len(override.Ports) > 0 {
		result.Ports = override.Ports
	}
	if len(override.Volumes) > 0 {
		result.Volumes = override.Volumes
	}
	if override.Restart != "" {
		result.Restart = override.Restart
	}
	if override.HealthCheck != nil {
		result.HealthCheck = override.HealthCheck
	}
	if override.Deploy != nil {
		result.Deploy = override.Deploy
	}
	// Merge labels
	if len(override.Labels) > 0 {
		if result.Labels == nil {
			result.Labels = make(map[string]string)
		}
		for k, v := range override.Labels {
			result.Labels[k] = v
		}
	}

	return result
}
