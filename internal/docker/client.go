// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package docker provides a wrapper around the Docker SDK for container management.
// It handles connection pooling, timeout management, and provides a simplified API
// for container, image, volume, and network operations.
package docker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

const (
	// DefaultTimeout is the default timeout for Docker API operations
	DefaultTimeout = 30 * time.Second

	// DefaultAPIVersion is the minimum Docker API version we support
	// We use API version negotiation, so this is a fallback
	DefaultAPIVersion = "1.45"

	// DefaultLocalSocketPath is the standard Unix socket path for Docker.
	// Override at runtime via SetLocalSocketPath for rootless Docker or custom locations.
	DefaultLocalSocketPath = "/var/run/docker.sock"

	// DefaultPingTimeout is the timeout for ping operations
	DefaultPingTimeout = 5 * time.Second
)

// localSocketPath holds the active Docker socket path.
// Defaults to DefaultLocalSocketPath; override via SetLocalSocketPath.
var localSocketPath = DefaultLocalSocketPath

// LocalSocketPath returns the configured Docker socket path.
func LocalSocketPath() string {
	return localSocketPath
}

// SetLocalSocketPath overrides the default Docker socket path.
// Call this at application startup before creating any Docker clients.
func SetLocalSocketPath(path string) {
	if path != "" {
		localSocketPath = path
	}
}

// ClientOptions configures a Docker client connection
type ClientOptions struct {
	// Host is the Docker daemon address (e.g. unix:///var/run/docker.sock or tcp://host:2375)
	Host string

	// APIVersion is the Docker API version to use (empty for auto-negotiation)
	APIVersion string

	// TLS configuration for TCP connections
	TLS *TLSConfig

	// Timeout for API operations (default: 30s)
	Timeout time.Duration

	// Headers to send with every request
	Headers map[string]string
}

// TLSConfig holds TLS configuration for secure Docker connections
type TLSConfig struct {
	// CACert is the CA certificate for verifying the server
	CACert []byte

	// ClientCert is the client certificate for authentication
	ClientCert []byte

	// ClientKey is the client private key
	ClientKey []byte

	// InsecureSkipVerify disables server certificate verification
	InsecureSkipVerify bool
}

// Client wraps the Docker SDK client with additional functionality
type Client struct {
	cli        *client.Client
	host       string
	apiVersion string
	timeout    time.Duration
	mu         sync.RWMutex
	closed     bool
}

// NewClient creates a new Docker client with the given options
func NewClient(ctx context.Context, opts ClientOptions) (*Client, error) {
	log := logger.FromContext(ctx)

	// Apply defaults
	if opts.Host == "" {
		opts.Host = "unix://" + localSocketPath
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	log.Debug("Creating Docker client",
		"host", opts.Host,
		"timeout", opts.Timeout,
	)

	// Build client options
	clientOpts := []client.Opt{
		client.WithHost(opts.Host),
		client.WithAPIVersionNegotiation(),
	}

	// Configure HTTP client based on connection type
	httpClient, err := buildHTTPClient(opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDockerConnection, "failed to build HTTP client")
	}
	if httpClient != nil {
		clientOpts = append(clientOpts, client.WithHTTPClient(httpClient))
	}

	// Set API version if specified
	if opts.APIVersion != "" {
		clientOpts = append(clientOpts, client.WithVersion(opts.APIVersion))
	}

	// Set custom headers
	if len(opts.Headers) > 0 {
		clientOpts = append(clientOpts, client.WithHTTPHeaders(opts.Headers))
	}

	// Add HTTPS scheme for TLS connections
	if opts.TLS != nil && strings.HasPrefix(opts.Host, "tcp://") {
		clientOpts = append(clientOpts, client.WithScheme("https"))
	}

	// Create the client
	cli, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDockerConnection, "failed to create Docker client")
	}

	// Verify connection with ping
	pingCtx, cancel := context.WithTimeout(ctx, DefaultPingTimeout)
	defer cancel()

	if _, err := cli.Ping(pingCtx); err != nil {
		cli.Close()
		return nil, errors.Wrap(err, errors.CodeDockerConnection, "failed to ping Docker daemon")
	}

	// Get negotiated API version
	apiVersion := cli.ClientVersion()
	log.Debug("Docker client created",
		"api_version", apiVersion,
		"host", opts.Host,
	)

	return &Client{
		cli:        cli,
		host:       opts.Host,
		apiVersion: apiVersion,
		timeout:    opts.Timeout,
	}, nil
}

// NewLocalClient creates a client connected to the local Docker socket
func NewLocalClient(ctx context.Context) (*Client, error) {
	return NewClient(ctx, ClientOptions{
		Host:    "unix://" + localSocketPath,
		Timeout: DefaultTimeout,
	})
}

// buildHTTPClient creates an HTTP client based on connection options
func buildHTTPClient(opts ClientOptions) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure for Unix socket
	if isUnixSocket(opts.Host) {
		socketPath := strings.TrimPrefix(opts.Host, "unix://")
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: opts.Timeout,
			}
			return dialer.DialContext(ctx, "unix", socketPath)
		}
	}

	// Configure TLS for TCP connections
	if opts.TLS != nil {
		tlsConfig, err := buildTLSConfig(opts.TLS)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}, nil
}

// buildTLSConfig creates a TLS configuration from TLSConfig
func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Load CA certificate
	if len(cfg.CACert) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate
	if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// isUnixSocket checks if the host is a Unix socket path
func isUnixSocket(host string) bool {
	return strings.HasPrefix(host, "unix://")
}

// Raw returns the underlying Docker SDK client
// Use with caution - prefer using the wrapper methods
func (c *Client) Raw() *client.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cli
}

// Host returns the Docker host address
func (c *Client) Host() string {
	return c.host
}

// APIVersion returns the negotiated API version
func (c *Client) APIVersion() string {
	return c.apiVersion
}

// Timeout returns the configured timeout
func (c *Client) Timeout() time.Duration {
	return c.timeout
}

// Ping checks Docker daemon connectivity
func (c *Client) Ping(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	_, err := c.cli.Ping(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDockerConnection, "ping failed")
	}
	return nil
}

// Info returns Docker system information
func (c *Client) Info(ctx context.Context) (*DockerInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	info, err := c.cli.Info(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDockerConnection, "failed to get Docker info")
	}

	// Extract sorted runtime names from the map
	var runtimes []string
	for name := range info.Runtimes {
		runtimes = append(runtimes, name)
	}
	sort.Strings(runtimes)

	return &DockerInfo{
		ID:                info.ID,
		Name:              info.Name,
		ServerVersion:     info.ServerVersion,
		APIVersion:        c.apiVersion,
		OS:                info.OperatingSystem,
		OSType:            info.OSType,
		Architecture:      info.Architecture,
		KernelVersion:     info.KernelVersion,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		MemTotal:          info.MemTotal,
		NCPU:              info.NCPU,
		DockerRootDir:     info.DockerRootDir,
		StorageDriver:     info.Driver,
		LoggingDriver:     info.LoggingDriver,
		CgroupDriver:      info.CgroupDriver,
		CgroupVersion:     info.CgroupVersion,
		DefaultRuntime:    info.DefaultRuntime,
		SecurityOptions:   info.SecurityOptions,
		Runtimes:          runtimes,
		Swarm:             info.Swarm.ControlAvailable,
		RegistryConfig:    info.RegistryConfig,
	}, nil
}

// ServerVersion returns the Docker server version
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	version, err := c.cli.ServerVersion(ctx)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeDockerConnection, "failed to get server version")
	}
	return version.Version, nil
}

// Close closes the Docker client connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	if c.cli != nil {
		return c.cli.Close()
	}
	return nil
}

// BuildCachePrune removes build cache entries from the Docker daemon.
// It returns the total bytes freed and an error if the operation fails.
func (c *Client) BuildCachePrune(ctx context.Context, all bool) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return 0, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	report, err := c.cli.BuildCachePrune(ctx, types.BuildCachePruneOptions{
		All: all,
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to prune build cache")
	}

	return int64(report.SpaceReclaimed), nil
}

// IsClosed returns true if the client has been closed
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// ClientPool manages multiple Docker clients, one per host
type ClientPool struct {
	clients map[string]*Client
	mu      sync.RWMutex
}

// NewClientPool creates a new client pool
func NewClientPool() *ClientPool {
	return &ClientPool{
		clients: make(map[string]*Client),
	}
}

// Get retrieves a client for the given host ID
func (p *ClientPool) Get(hostID string) (*Client, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	c, ok := p.clients[hostID]
	return c, ok
}

// HostIDs returns a list of all registered host IDs in the pool.
func (p *ClientPool) HostIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.clients))
	for id := range p.clients {
		ids = append(ids, id)
	}
	return ids
}

// GetOrCreate retrieves an existing client or creates a new one
func (p *ClientPool) GetOrCreate(ctx context.Context, hostID string, opts ClientOptions) (*Client, error) {
	// Try to get existing client first
	p.mu.RLock()
	if c, ok := p.clients[hostID]; ok {
		p.mu.RUnlock()
		// Verify the client is still working
		if err := c.Ping(ctx); err == nil {
			return c, nil
		}
		// Client is dead, remove it
		p.Remove(hostID)
	} else {
		p.mu.RUnlock()
	}

	// Create new client
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := p.clients[hostID]; ok {
		return c, nil
	}

	client, err := NewClient(ctx, opts)
	if err != nil {
		return nil, err
	}

	p.clients[hostID] = client
	return client, nil
}

// Set adds or replaces a client in the pool
func (p *ClientPool) Set(hostID string, client *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close existing client if present
	if existing, ok := p.clients[hostID]; ok {
		existing.Close()
	}

	p.clients[hostID] = client
}

// Remove removes and closes a client from the pool
func (p *ClientPool) Remove(hostID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[hostID]; ok {
		c.Close()
		delete(p.clients, hostID)
	}
}

// CloseAll closes all clients in the pool
func (p *ClientPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.clients {
		c.Close()
	}
	p.clients = make(map[string]*Client)
}

// Size returns the number of clients in the pool
func (p *ClientPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.clients)
}

// Hosts returns a list of all host IDs in the pool
func (p *ClientPool) Hosts() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	hosts := make([]string, 0, len(p.clients))
	for hostID := range p.clients {
		hosts = append(hosts, hostID)
	}
	return hosts
}

// HealthCheck checks connectivity of all clients in the pool
// Returns a map of hostID -> error (nil if healthy)
func (p *ClientPool) HealthCheck(ctx context.Context) map[string]error {
	p.mu.RLock()
	clients := make(map[string]*Client, len(p.clients))
	for k, v := range p.clients {
		clients[k] = v
	}
	p.mu.RUnlock()

	results := make(map[string]error, len(clients))
	var wg sync.WaitGroup
	var resultsMu sync.Mutex

	for hostID, c := range clients {
		wg.Add(1)
		go func(id string, cli *Client) {
			defer wg.Done()
			err := cli.Ping(ctx)
			resultsMu.Lock()
			results[id] = err
			resultsMu.Unlock()
		}(hostID, c)
	}

	wg.Wait()
	return results
}
