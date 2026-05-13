// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/volume"
)

// Type aliases for Docker SDK types that we expose
type (
	// ImageImportSource is a type alias for Docker SDK's image.ImportSource
	ImageImportSource = image.ImportSource

	// ImageBuildOptions is a type alias for Docker SDK's types.ImageBuildOptions
	ImageBuildOptions = types.ImageBuildOptions

	// ImageBuildResponse is a type alias for Docker SDK's types.ImageBuildResponse
	ImageBuildResponse = types.ImageBuildResponse
)

// DockerInfo represents Docker daemon information
type DockerInfo struct {
	ID                string
	Name              string
	ServerVersion     string
	APIVersion        string
	OS                string
	OSType            string
	Architecture      string
	KernelVersion     string
	Containers        int
	ContainersRunning int
	ContainersPaused  int
	ContainersStopped int
	Images            int
	MemTotal          int64
	NCPU              int
	DockerRootDir     string
	StorageDriver     string
	LoggingDriver     string
	CgroupDriver      string
	CgroupVersion     string
	DefaultRuntime    string
	SecurityOptions   []string
	Runtimes          []string
	Swarm             bool
	RegistryConfig    *registry.ServiceConfig
}

// Container represents a Docker container
type Container struct {
	ID            string
	Name          string
	Image         string
	ImageID       string
	Command       string
	Status        string
	State         string
	Health        string
	Created       time.Time
	Started       time.Time
	Finished      time.Time
	Ports         []Port
	Labels        map[string]string
	Mounts        []Mount
	Networks      []NetworkAttachment
	RestartPolicy string
	RestartCount  int
	Platform      string
	SizeRw        int64
	SizeRootFs    int64
}

// ContainerDetails contains detailed container information from inspect
type ContainerDetails struct {
	Container
	Config          *ContainerConfig
	HostConfig      *HostConfig
	NetworkMode     string
	Driver          string
	MountLabel      string
	ProcessLabel    string
	AppArmorProfile string
	ExecIDs         []string
	LogPath         string
	Args            []string
	Path            string
}

// ContainerConfig represents container configuration
type ContainerConfig struct {
	Hostname    string
	Domainname  string
	User        string
	AttachStdin bool
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	OpenStdin    bool
	StdinOnce    bool
	Env          []string
	Cmd          []string
	Entrypoint   []string
	Image        string
	Labels       map[string]string
	Volumes      map[string]struct{}
	WorkingDir   string
	StopSignal   string
	StopTimeout  *int
	Healthcheck  *HealthConfig
}

// HostConfig represents container host configuration
type HostConfig struct {
	Binds           []string
	NetworkMode     string
	PortBindings    map[string][]PortBinding
	RestartPolicy   RestartPolicy
	AutoRemove      bool
	VolumeDriver    string
	VolumesFrom     []string
	CapAdd          []string
	CapDrop         []string
	DNS             []string
	DNSOptions      []string
	DNSSearch       []string
	ExtraHosts      []string
	GroupAdd        []string
	IpcMode         string
	Links           []string
	OomScoreAdj     int
	PidMode         string
	Privileged      bool
	PublishAllPorts bool
	ReadonlyRootfs  bool
	SecurityOpt     []string
	Tmpfs           map[string]string
	UTSMode         string
	UsernsMode      string
	ShmSize         int64
	Sysctls         map[string]string
	Runtime         string
	Isolation       string
	Resources       Resources
	Mounts          []MountConfig
	LogConfig       LogConfig
	Devices         []DeviceMapping
}

// DeviceMapping represents a device mapping from host to container
type DeviceMapping struct {
	PathOnHost        string
	PathInContainer   string
	CgroupPermissions string
}

// Resources represents container resource constraints
type Resources struct {
	CPUShares          int64
	Memory             int64
	NanoCPUs           int64
	CPUPeriod          int64
	CPUQuota           int64
	CPURealtimePeriod  int64
	CPURealtimeRuntime int64
	CpusetCpus         string
	CpusetMems         string
	MemoryReservation  int64
	MemorySwap         int64
	MemorySwappiness   *int64
	OomKillDisable     *bool
	PidsLimit          *int64
}

// RestartPolicy represents container restart policy
type RestartPolicy struct {
	Name              string
	MaximumRetryCount int
}

// LogConfig represents container logging configuration
type LogConfig struct {
	Type   string
	Config map[string]string
}

// MountConfig represents a mount configuration
type MountConfig struct {
	Type        string
	Source      string
	Target      string
	ReadOnly    bool
	Consistency string
}

// HealthConfig represents container health check configuration
type HealthConfig struct {
	Test        []string
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration
	Retries     int
}

// Port represents a container port mapping
type Port struct {
	PrivatePort uint16
	PublicPort  uint16
	Type        string
	IP          string
}

// PortBinding represents a port binding
type PortBinding struct {
	HostIP   string
	HostPort string
}

// Mount represents a container mount point
type Mount struct {
	Type        string
	Name        string
	Source      string
	Destination string
	Driver      string
	Mode        string
	RW          bool
	Propagation string
}

// NetworkAttachment represents a container's network attachment
type NetworkAttachment struct {
	NetworkID           string
	NetworkName         string
	EndpointID          string
	IPAddress           string
	IPPrefixLen         int
	IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	Gateway             string
	MacAddress          string
	Aliases             []string
}

// Image represents a Docker image
type Image struct {
	ID          string
	ParentID    string
	RepoTags    []string
	RepoDigests []string
	Created     time.Time
	Size        int64
	SharedSize  int64
	VirtualSize int64
	Labels      map[string]string
	Containers  int64
}

// ImageDetails contains detailed image information from inspect
type ImageDetails struct {
	Image
	Architecture  string
	Author        string
	Comment       string
	Config        *ContainerConfig
	Container     string
	DockerVersion string
	OS            string
	RootFS        RootFS
	Metadata      ImageMetadata
}

// RootFS represents image root filesystem
type RootFS struct {
	Type   string
	Layers []string
}

// ImageMetadata represents image metadata
type ImageMetadata struct {
	LastTagTime time.Time
}

// Volume represents a Docker volume
type Volume struct {
	Name       string
	Driver     string
	Mountpoint string
	Labels     map[string]string
	Scope      string
	Options    map[string]string
	Status     map[string]interface{}
	CreatedAt  time.Time
	UsageData  *VolumeUsage
}

// VolumeUsage represents volume usage data
type VolumeUsage struct {
	Size     int64
	RefCount int64
}

// Network represents a Docker network
type Network struct {
	ID         string
	Name       string
	Driver     string
	Scope      string
	EnableIPv6 bool
	Internal   bool
	Attachable bool
	Ingress    bool
	ConfigFrom NetworkConfigReference
	ConfigOnly bool
	IPAM       IPAMConfig
	Options    map[string]string
	Labels     map[string]string
	Containers map[string]NetworkContainer
	Created    time.Time
}

// NetworkConfigReference represents network config reference
type NetworkConfigReference struct {
	Network string
}

// IPAMConfig represents IPAM configuration
type IPAMConfig struct {
	Driver  string
	Config  []IPAMPoolConfig
	Options map[string]string
}

// IPAMPoolConfig represents IPAM pool configuration
type IPAMPoolConfig struct {
	Subnet     string
	IPRange    string
	Gateway    string
	AuxAddress map[string]string
}

// NetworkContainer represents a container connected to a network
type NetworkContainer struct {
	Name        string
	EndpointID  string
	MacAddress  string
	IPv4Address string
	IPv6Address string
}

// ContainerStats represents real-time container statistics
type ContainerStats struct {
	ID            string
	Name          string
	Read          time.Time
	PreRead       time.Time
	CPUPercent    float64
	MemoryUsage   uint64
	MemoryLimit   uint64
	MemoryPercent float64
	NetworkRx     uint64
	NetworkTx     uint64
	BlockRead     uint64
	BlockWrite    uint64
	PIDs          uint64
}

// LogLine represents a single log line
type LogLine struct {
	Stream    string // "stdout" or "stderr"
	Timestamp time.Time
	Message   string
}

// ExecResult represents the result of a container exec command
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// CommitOptions represents options for committing a container to an image
type CommitOptions struct {
	Reference string            // image:tag
	Comment   string
	Author    string
	Pause     bool
	Changes   []string          // Dockerfile instructions to apply
	Config    *ContainerConfig
}

// PullProgress represents image pull progress
type PullProgress struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Progress       string `json:"progress"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
	Error string `json:"error,omitempty"`
}

// ============================================================================
// Conversion functions - Docker SDK types to our types
// ============================================================================

// ContainerFromSummary converts a Docker container summary to our Container type
func ContainerFromSummary(c types.Container) Container {
	cont := Container{
		ID:         c.ID,
		Image:      c.Image,
		ImageID:    c.ImageID,
		Command:    c.Command,
		Status:     c.Status,
		State:      string(c.State),
		Created:    time.Unix(c.Created, 0),
		Labels:     c.Labels,
		SizeRw:     c.SizeRw,
		SizeRootFs: c.SizeRootFs,
	}

	// Extract name (remove leading /)
	if len(c.Names) > 0 {
		cont.Name = c.Names[0]
		if len(cont.Name) > 0 && cont.Name[0] == '/' {
			cont.Name = cont.Name[1:]
		}
	}

	// Convert ports
	for _, p := range c.Ports {
		cont.Ports = append(cont.Ports, Port{
			PrivatePort: p.PrivatePort,
			PublicPort:  p.PublicPort,
			Type:        p.Type,
			IP:          p.IP,
		})
	}

	// Convert mounts
	for _, m := range c.Mounts {
		cont.Mounts = append(cont.Mounts, Mount{
			Type:        string(m.Type),
			Name:        m.Name,
			Source:      m.Source,
			Destination: m.Destination,
			Driver:      m.Driver,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: string(m.Propagation),
		})
	}

	// Convert network settings
	if c.NetworkSettings != nil {
		for netName, netSettings := range c.NetworkSettings.Networks {
			cont.Networks = append(cont.Networks, NetworkAttachment{
				NetworkID:           netSettings.NetworkID,
				NetworkName:         netName,
				EndpointID:          netSettings.EndpointID,
				IPAddress:           netSettings.IPAddress,
				IPPrefixLen:         netSettings.IPPrefixLen,
				IPv6Gateway:         netSettings.IPv6Gateway,
				GlobalIPv6Address:   netSettings.GlobalIPv6Address,
				GlobalIPv6PrefixLen: netSettings.GlobalIPv6PrefixLen,
				Gateway:             netSettings.Gateway,
				MacAddress:          netSettings.MacAddress,
				Aliases:             netSettings.Aliases,
			})
		}
	}

	return cont
}

// ContainerFromInspect converts a Docker container inspect response to ContainerDetails
func ContainerFromInspect(c types.ContainerJSON) ContainerDetails {
	details := ContainerDetails{
		Container: Container{
			ID:      c.ID,
			Image:   c.Config.Image,
			ImageID: c.Image,
			Status:  string(c.State.Status),
			State:   string(c.State.Status),
			Labels:  c.Config.Labels,
		},
		Driver:       c.Driver,
		MountLabel:   c.MountLabel,
		ProcessLabel: c.ProcessLabel,
		LogPath:      c.LogPath,
		Path:         c.Path,
		Args:         c.Args,
	}

	// Extract name (remove leading /)
	if len(c.Name) > 0 && c.Name[0] == '/' {
		details.Name = c.Name[1:]
	} else {
		details.Name = c.Name
	}

	// Parse timestamps (SDK returns strings in RFC3339Nano format)
	if c.Created != "" {
		if t, err := time.Parse(time.RFC3339Nano, c.Created); err == nil {
			details.Created = t
		}
	}

	if c.State != nil {
		if c.State.StartedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, c.State.StartedAt); err == nil {
				details.Started = t
			}
		}
		if c.State.FinishedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, c.State.FinishedAt); err == nil {
				details.Finished = t
			}
		}
		if c.State.Health != nil {
			details.Health = string(c.State.Health.Status)
		}
	}

	// Convert mounts
	for _, m := range c.Mounts {
		details.Mounts = append(details.Mounts, Mount{
			Type:        string(m.Type),
			Name:        m.Name,
			Source:      m.Source,
			Destination: m.Destination,
			Driver:      m.Driver,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: string(m.Propagation),
		})
	}

	// Convert networks
	if c.NetworkSettings != nil {
		for netName, netSettings := range c.NetworkSettings.Networks {
			details.Networks = append(details.Networks, NetworkAttachment{
				NetworkID:   netSettings.NetworkID,
				NetworkName: netName,
				EndpointID:  netSettings.EndpointID,
				IPAddress:   netSettings.IPAddress,
				IPPrefixLen: netSettings.IPPrefixLen,
				Gateway:     netSettings.Gateway,
				MacAddress:  netSettings.MacAddress,
				Aliases:     netSettings.Aliases,
			})
		}

		// Convert port bindings from NetworkSettings (live bound ports).
		// This mirrors ContainerFromSummary which gets ports pre-parsed from the list API.
		for natPort, bindings := range c.NetworkSettings.Ports {
			privatePort, _ := strconv.ParseUint(natPort.Port(), 10, 16)
			proto := natPort.Proto()
			if len(bindings) == 0 {
				// Exposed but not published (no host binding)
				details.Ports = append(details.Ports, Port{
					PrivatePort: uint16(privatePort),
					Type:        proto,
				})
				continue
			}
			for _, b := range bindings {
				hostPort, _ := strconv.ParseUint(b.HostPort, 10, 16)
				details.Ports = append(details.Ports, Port{
					PrivatePort: uint16(privatePort),
					PublicPort:  uint16(hostPort),
					Type:        proto,
					IP:          b.HostIP,
				})
			}
		}
	}

	// Host config
	if c.HostConfig != nil {
		details.NetworkMode = string(c.HostConfig.NetworkMode)
		details.RestartPolicy = string(c.HostConfig.RestartPolicy.Name)
		details.RestartCount = c.RestartCount

		hc := &HostConfig{
			Binds:           c.HostConfig.Binds,
			NetworkMode:     string(c.HostConfig.NetworkMode),
			AutoRemove:      c.HostConfig.AutoRemove,
			VolumeDriver:    c.HostConfig.VolumeDriver,
			VolumesFrom:     c.HostConfig.VolumesFrom,
			CapAdd:          c.HostConfig.CapAdd,
			CapDrop:         c.HostConfig.CapDrop,
			DNS:             c.HostConfig.DNS,
			DNSOptions:      c.HostConfig.DNSOptions,
			DNSSearch:       c.HostConfig.DNSSearch,
			ExtraHosts:      c.HostConfig.ExtraHosts,
			GroupAdd:        c.HostConfig.GroupAdd,
			IpcMode:         string(c.HostConfig.IpcMode),
			OomScoreAdj:     c.HostConfig.OomScoreAdj,
			PidMode:         string(c.HostConfig.PidMode),
			Privileged:      c.HostConfig.Privileged,
			PublishAllPorts: c.HostConfig.PublishAllPorts,
			ReadonlyRootfs:  c.HostConfig.ReadonlyRootfs,
			SecurityOpt:     c.HostConfig.SecurityOpt,
			Tmpfs:           c.HostConfig.Tmpfs,
			UTSMode:         string(c.HostConfig.UTSMode),
			UsernsMode:      string(c.HostConfig.UsernsMode),
			ShmSize:         c.HostConfig.ShmSize,
			Sysctls:         c.HostConfig.Sysctls,
			Runtime:         c.HostConfig.Runtime,
			Isolation:       string(c.HostConfig.Isolation),
			RestartPolicy: RestartPolicy{
				Name:              string(c.HostConfig.RestartPolicy.Name),
				MaximumRetryCount: c.HostConfig.RestartPolicy.MaximumRetryCount,
			},
			Resources: Resources{
				CPUShares:          c.HostConfig.Resources.CPUShares,
				Memory:             c.HostConfig.Resources.Memory,
				NanoCPUs:           c.HostConfig.Resources.NanoCPUs,
				CPUPeriod:          c.HostConfig.Resources.CPUPeriod,
				CPUQuota:           c.HostConfig.Resources.CPUQuota,
				CpusetCpus:         c.HostConfig.Resources.CpusetCpus,
				CpusetMems:         c.HostConfig.Resources.CpusetMems,
				MemoryReservation:  c.HostConfig.Resources.MemoryReservation,
				MemorySwap:         c.HostConfig.Resources.MemorySwap,
				MemorySwappiness:   c.HostConfig.Resources.MemorySwappiness,
				OomKillDisable:     c.HostConfig.Resources.OomKillDisable,
				PidsLimit:          c.HostConfig.Resources.PidsLimit,
			},
		}

		// Convert port bindings
		if c.HostConfig.PortBindings != nil {
			hc.PortBindings = make(map[string][]PortBinding)
			for port, bindings := range c.HostConfig.PortBindings {
				key := string(port)
				for _, b := range bindings {
					hc.PortBindings[key] = append(hc.PortBindings[key], PortBinding{
						HostIP:   b.HostIP,
						HostPort: b.HostPort,
					})
				}
			}
		}

		// Convert devices
		for _, d := range c.HostConfig.Resources.Devices {
			hc.Devices = append(hc.Devices, DeviceMapping{
				PathOnHost:        d.PathOnHost,
				PathInContainer:   d.PathInContainer,
				CgroupPermissions: d.CgroupPermissions,
			})
		}

		// Convert log config
		hc.LogConfig = LogConfig{
			Type:   c.HostConfig.LogConfig.Type,
			Config: c.HostConfig.LogConfig.Config,
		}

		// Convert mount configs
		for _, m := range c.HostConfig.Mounts {
			hc.Mounts = append(hc.Mounts, MountConfig{
				Type:     string(m.Type),
				Source:   m.Source,
				Target:   m.Target,
				ReadOnly: m.ReadOnly,
			})
		}

		details.HostConfig = hc
	}

	// Config
	if c.Config != nil {
		details.Config = &ContainerConfig{
			Hostname:   c.Config.Hostname,
			Domainname: c.Config.Domainname,
			User:       c.Config.User,
			Env:        c.Config.Env,
			Cmd:        c.Config.Cmd,
			Entrypoint: c.Config.Entrypoint,
			Image:      c.Config.Image,
			Labels:     c.Config.Labels,
			WorkingDir: c.Config.WorkingDir,
			Tty:        c.Config.Tty,
			OpenStdin:  c.Config.OpenStdin,
		}
		if c.Config.Volumes != nil {
			details.Config.Volumes = c.Config.Volumes
		}
		if c.Config.StopSignal != "" {
			details.Config.StopSignal = c.Config.StopSignal
		}
		if c.Config.StopTimeout != nil {
			details.Config.StopTimeout = c.Config.StopTimeout
		}
	}

	return details
}

// ImageFromSummary converts a Docker image summary to our Image type
func ImageFromSummary(i image.Summary) Image {
	return Image{
		ID:          i.ID,
		ParentID:    i.ParentID,
		RepoTags:    i.RepoTags,
		RepoDigests: i.RepoDigests,
		Created:     time.Unix(i.Created, 0),
		Size:        i.Size,
		SharedSize:  i.SharedSize,
		VirtualSize: i.VirtualSize,
		Labels:      i.Labels,
		Containers:  i.Containers,
	}
}

// ImageFromInspect converts a Docker image inspect response to ImageDetails
func ImageFromInspect(i types.ImageInspect) ImageDetails {
	details := ImageDetails{
		Image: Image{
			ID:          i.ID,
			ParentID:    i.Parent,
			RepoTags:    i.RepoTags,
			RepoDigests: i.RepoDigests,
			Created:     time.Time{},
			Size:        i.Size,
			VirtualSize: i.VirtualSize,
			Labels:      nil,
		},
		Architecture:  i.Architecture,
		Author:        i.Author,
		Comment:       i.Comment,
		Container:     i.Container,
		DockerVersion: i.DockerVersion,
		OS:            i.Os,
	}

	// Parse created time
	if t, err := time.Parse(time.RFC3339Nano, i.Created); err == nil {
		details.Created = t
	}

	// Config labels
	if i.Config != nil {
		details.Labels = i.Config.Labels
	}

	// RootFS
	if i.RootFS.Type != "" {
		details.RootFS = RootFS{
			Type:   i.RootFS.Type,
			Layers: i.RootFS.Layers,
		}
	}

	// Metadata
	if i.Metadata.LastTagTime != (time.Time{}) {
		details.Metadata.LastTagTime = i.Metadata.LastTagTime
	}

	return details
}

// VolumeFromDocker converts a Docker volume to our Volume type
func VolumeFromDocker(v volume.Volume) Volume {
	vol := Volume{
		Name:       v.Name,
		Driver:     v.Driver,
		Mountpoint: v.Mountpoint,
		Labels:     v.Labels,
		Scope:      v.Scope,
		Options:    v.Options,
		Status:     v.Status,
	}

	// Parse created time
	if v.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, v.CreatedAt); err == nil {
			vol.CreatedAt = t
		}
	}

	// Usage data
	if v.UsageData != nil {
		vol.UsageData = &VolumeUsage{
			Size:     v.UsageData.Size,
			RefCount: v.UsageData.RefCount,
		}
	}

	return vol
}

// NetworkFromDocker converts a Docker network to our Network type
func NetworkFromDocker(n network.Inspect) Network {
	net := Network{
		ID:         n.ID,
		Name:       n.Name,
		Driver:     n.Driver,
		Scope:      n.Scope,
		EnableIPv6: n.EnableIPv6,
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Ingress:    n.Ingress,
		ConfigOnly: n.ConfigOnly,
		Options:    n.Options,
		Labels:     n.Labels,
		Containers: make(map[string]NetworkContainer),
		Created:    n.Created,
	}

	// Config reference
	if n.ConfigFrom.Network != "" {
		net.ConfigFrom.Network = n.ConfigFrom.Network
	}

	// IPAM config
	if n.IPAM.Driver != "" {
		net.IPAM.Driver = n.IPAM.Driver
		net.IPAM.Options = n.IPAM.Options
		for _, cfg := range n.IPAM.Config {
			net.IPAM.Config = append(net.IPAM.Config, IPAMPoolConfig{
				Subnet:     cfg.Subnet,
				IPRange:    cfg.IPRange,
				Gateway:    cfg.Gateway,
				AuxAddress: cfg.AuxAddress,
			})
		}
	}

	// Containers
	for id, c := range n.Containers {
		net.Containers[id] = NetworkContainer{
			Name:        c.Name,
			EndpointID:  c.EndpointID,
			MacAddress:  c.MacAddress,
			IPv4Address: c.IPv4Address,
			IPv6Address: c.IPv6Address,
		}
	}

	return net
}

// NetworkFromResource converts a Docker network resource (from list) to our Network type
// Note: In SDK v28.5+, network.Summary is an alias for network.Inspect
func NetworkFromResource(n network.Inspect) Network {
	return NetworkFromDocker(n)
}

// CalculateCPUPercent calculates CPU percentage from container stats
// Formula from Docker CLI: https://github.com/docker/cli/blob/master/cli/command/container/stats_helpers.go
func CalculateCPUPercent(stats *container.StatsResponse) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

	if systemDelta > 0 && cpuDelta > 0 {
		// Calculate CPU count
		cpuCount := float64(stats.CPUStats.OnlineCPUs)
		if cpuCount == 0 {
			cpuCount = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
		}
		if cpuCount == 0 {
			cpuCount = 1
		}

		return (cpuDelta / systemDelta) * cpuCount * 100.0
	}
	return 0.0
}

// CalculateMemoryPercent calculates memory usage percentage
func CalculateMemoryPercent(stats *container.StatsResponse) float64 {
	if stats.MemoryStats.Limit > 0 {
		return float64(stats.MemoryStats.Usage) / float64(stats.MemoryStats.Limit) * 100.0
	}
	return 0.0
}

// StatsFromResponse converts a Docker stats response to our ContainerStats type
func StatsFromResponse(containerID string, stats *container.StatsResponse) ContainerStats {
	// Calculate network I/O
	var networkRx, networkTx uint64
	for _, netStats := range stats.Networks {
		networkRx += netStats.RxBytes
		networkTx += netStats.TxBytes
	}

	// Calculate block I/O
	var blockRead, blockWrite uint64
	for _, blk := range stats.BlkioStats.IoServiceBytesRecursive {
		switch blk.Op {
		case "Read", "read":
			blockRead += blk.Value
		case "Write", "write":
			blockWrite += blk.Value
		}
	}

	return ContainerStats{
		ID:            containerID,
		Read:          stats.Read,
		PreRead:       stats.PreRead,
		CPUPercent:    CalculateCPUPercent(stats),
		MemoryUsage:   stats.MemoryStats.Usage,
		MemoryLimit:   stats.MemoryStats.Limit,
		MemoryPercent: CalculateMemoryPercent(stats),
		NetworkRx:     networkRx,
		NetworkTx:     networkTx,
		BlockRead:     blockRead,
		BlockWrite:    blockWrite,
		PIDs:          stats.PidsStats.Current,
	}
}

// ============================================================================
// Swarm Types
// ============================================================================

// SwarmClusterState represents the current state of the Swarm cluster
type SwarmClusterState struct {
	Active           bool   `json:"active"`
	ClusterID        string `json:"cluster_id,omitempty"`
	NodeID           string `json:"node_id"`
	NodeAddr         string `json:"node_addr"`
	IsManager        bool   `json:"is_manager"`
	Managers         int    `json:"managers"`
	Nodes            int    `json:"nodes"`
	LocalNodeState   string `json:"local_node_state"`   // inactive, pending, active, error, locked
	Error            string `json:"error,omitempty"`
}

// SwarmNodeInfo represents a Swarm cluster node
type SwarmNodeInfo struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	Role          string `json:"role"`          // manager, worker
	Status        string `json:"status"`        // ready, down, disconnected, unknown
	Availability  string `json:"availability"`  // active, pause, drain
	EngineVersion string `json:"engine_version"`
	Address       string `json:"address"`
	IsLeader      bool   `json:"is_leader"`
	NCPU          int64  `json:"ncpu"`
	MemoryBytes   int64  `json:"memory_bytes"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
}

// SwarmServiceCreateOptions defines options for creating a Swarm service
type SwarmServiceCreateOptions struct {
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Replicas    uint64            `json:"replicas"`
	Command     []string          `json:"command,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Ports       []SwarmPortConfig `json:"ports,omitempty"`
	Constraints []string          `json:"constraints,omitempty"`
	Mounts      []SwarmMount      `json:"mounts,omitempty"`
}

// SwarmServiceUpdateOptions defines options for updating a Swarm service
type SwarmServiceUpdateOptions struct {
	Image       *string           `json:"image,omitempty"`
	Replicas    *uint64           `json:"replicas,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Ports       []SwarmPortConfig `json:"ports,omitempty"`
	Constraints []string          `json:"constraints,omitempty"`
}

// SwarmServiceInfo represents a Swarm service
type SwarmServiceInfo struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Mode            string            `json:"mode"`             // replicated, global
	ReplicasDesired uint64            `json:"replicas_desired"`
	ReplicasRunning uint64            `json:"replicas_running"`
	Ports           []SwarmPortConfig `json:"ports,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// SwarmTaskInfo represents a running task (container) in a Swarm service
type SwarmTaskInfo struct {
	ID           string    `json:"id"`
	ServiceID    string    `json:"service_id"`
	NodeID       string    `json:"node_id"`
	NodeHostname string    `json:"node_hostname,omitempty"`
	Status       string    `json:"status"`        // running, shutdown, failed, pending, etc.
	DesiredState string    `json:"desired_state"` // running, shutdown
	ContainerID  string    `json:"container_id,omitempty"`
	Image        string    `json:"image"`
	Error        string    `json:"error,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SwarmPortConfig represents a published port configuration
type SwarmPortConfig struct {
	Protocol      string `json:"protocol"`       // tcp, udp
	TargetPort    uint32 `json:"target_port"`
	PublishedPort uint32 `json:"published_port"`
	PublishMode   string `json:"publish_mode"`   // ingress, host
}

// SwarmMount represents a volume mount for a Swarm service
type SwarmMount struct {
	Type     string `json:"type"`     // bind, volume, tmpfs
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
