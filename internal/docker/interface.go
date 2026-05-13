// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package docker - ClientAPI defines the interface for Docker operations.
// Both the real Client (direct Docker connection) and AgentProxyClient
// (NATS gateway routing) implement this interface, enabling transparent
// multi-host Docker management.
package docker

import (
	"context"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/api/types/registry"
)

// ClientAPI is the interface for all Docker operations.
// It abstracts over direct Docker SDK connections and remote agent proxies.
type ClientAPI interface {
	// System operations
	Ping(ctx context.Context) error
	Info(ctx context.Context) (*DockerInfo, error)
	ServerVersion(ctx context.Context) (string, error)
	Close() error
	IsClosed() bool

	// Container lifecycle
	ContainerList(ctx context.Context, opts ContainerListOptions) ([]Container, error)
	ContainerGet(ctx context.Context, containerID string) (*ContainerDetails, error)
	ContainerInspectRaw(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerCreate(ctx context.Context, opts ContainerCreateOptions) (string, error)
	ContainerStart(ctx context.Context, containerID string) error
	ContainerStop(ctx context.Context, containerID string, timeout *int) error
	ContainerRestart(ctx context.Context, containerID string, timeout *int) error
	ContainerKill(ctx context.Context, containerID string, signal string) error
	ContainerPause(ctx context.Context, containerID string) error
	ContainerUnpause(ctx context.Context, containerID string) error
	ContainerRename(ctx context.Context, containerID, newName string) error
	ContainerRemove(ctx context.Context, containerID string, force bool, removeVolumes bool) error
	ContainerUpdate(ctx context.Context, containerID string, resources Resources) error
	ContainerPrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error)
	ContainerTop(ctx context.Context, containerID string, psArgs string) ([][]string, error)
	ContainerWait(ctx context.Context, containerID string) (int64, error)
	ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error)
	ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error)
	ContainerCommit(ctx context.Context, containerID string, options CommitOptions) (string, error)
	ContainerCopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader) error
	ContainerCopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error)
	WaitForHealthy(ctx context.Context, containerID string, timeout time.Duration) error

	// Image operations
	ImageList(ctx context.Context, opts ImageListOptions) ([]Image, error)
	ImageGet(ctx context.Context, imageID string) (*ImageDetails, error)
	ImagePull(ctx context.Context, ref string, opts ImagePullOptions) (<-chan PullProgress, error)
	ImagePullSync(ctx context.Context, ref string, opts ImagePullOptions) error
	ImagePush(ctx context.Context, ref string, registryAuth string) (<-chan PullProgress, error)
	ImageRemove(ctx context.Context, imageID string, force bool, pruneChildren bool) ([]image.DeleteResponse, error)
	ImageTag(ctx context.Context, source, target string) error
	ImagePrune(ctx context.Context, dangling bool, pruneFilters map[string][]string) (uint64, []image.DeleteResponse, error)
	ImageHistory(ctx context.Context, imageID string) ([]image.HistoryResponseItem, error)
	ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error)
	ImageLoad(ctx context.Context, input io.Reader, quiet bool) (image.LoadResponse, error)
	ImageSearch(ctx context.Context, term string, limit int, registryAuth string) ([]registry.SearchResult, error)
	ImageImport(ctx context.Context, source image.ImportSource, ref string, changes []string) (io.ReadCloser, error)
	ImageBuild(ctx context.Context, buildContext io.Reader, opts types.ImageBuildOptions) (types.ImageBuildResponse, error)
	ImageExists(ctx context.Context, ref string) (bool, error)
	ImageDigest(ctx context.Context, ref string) (string, error)
	ImageSize(ctx context.Context, ref string) (int64, error)

	// Build cache operations
	BuildCachePrune(ctx context.Context, all bool) (int64, error)

	// Volume operations
	VolumeList(ctx context.Context, opts VolumeListOptions) ([]Volume, error)
	VolumeGet(ctx context.Context, volumeName string) (*Volume, error)
	VolumeCreate(ctx context.Context, opts VolumeCreateOptions) (*Volume, error)
	VolumeRemove(ctx context.Context, volumeName string, force bool) error
	VolumePrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error)
	VolumeExists(ctx context.Context, volumeName string) (bool, error)
	VolumeUpdate(ctx context.Context, volumeName string, version uint64, opts volume.UpdateOptions) error
	VolumeUsedBy(ctx context.Context, volumeName string) ([]string, error)
	VolumeSize(ctx context.Context, volumeName string) (int64, error)

	// Network operations
	NetworkList(ctx context.Context, opts NetworkListOptions) ([]Network, error)
	NetworkGet(ctx context.Context, networkID string) (*Network, error)
	NetworkCreate(ctx context.Context, opts NetworkCreateOptions) (*Network, error)
	NetworkRemove(ctx context.Context, networkID string) error
	NetworkConnect(ctx context.Context, networkID string, opts NetworkConnectOptions) error
	NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error
	NetworkPrune(ctx context.Context, pruneFilters map[string][]string) ([]string, error)
	NetworkExists(ctx context.Context, networkID string) (bool, error)
	NetworkGetByName(ctx context.Context, name string) (*Network, error)
	NetworkTopology(ctx context.Context) (map[string][]string, error)

	// Exec operations
	ContainerExec(ctx context.Context, containerID string, cmd []string, opts ExecOptions) (*ExecResult, error)
	RunCommand(ctx context.Context, containerID string, cmd []string) (string, int, error)
	RunShellCommand(ctx context.Context, containerID string, command string) (string, int, error)
	ExecCreate(ctx context.Context, containerID string, config ExecConfig) (*ExecCreateResponse, error)
	ExecAttach(ctx context.Context, execID string) (types.HijackedResponse, error)
	ExecInspectByID(ctx context.Context, execID string) (*ExecInspect, error)

	// Log operations
	ContainerLogs(ctx context.Context, containerID string, opts LogOptions) (io.ReadCloser, error)
	ContainerLogsString(ctx context.Context, containerID string, opts LogOptions) (string, error)
	ContainerLogsLines(ctx context.Context, containerID string, lines int) ([]LogLine, error)
	ContainerLogsSince(ctx context.Context, containerID string, since time.Time) ([]LogLine, error)

	// Stats operations
	ContainerStatsOnce(ctx context.Context, containerID string) (*ContainerStats, error)
	MultiContainerStats(ctx context.Context, containerIDs []string) (map[string]*ContainerStats, error)
	AllContainerStats(ctx context.Context) (map[string]*ContainerStats, error)

	// Event operations
	GetEvents(ctx context.Context, since time.Time) ([]DockerEvent, error)
	StreamEvents(ctx context.Context) (<-chan DockerEvent, <-chan error)

	// Swarm operations
	SwarmInit(ctx context.Context, listenAddr, advertiseAddr string, forceNewCluster bool) (string, error)
	SwarmJoin(ctx context.Context, remoteAddr, joinToken, listenAddr string) error
	SwarmLeave(ctx context.Context, force bool) error
	SwarmInspect(ctx context.Context) (*SwarmClusterState, error)
	SwarmGetJoinTokens(ctx context.Context) (workerToken, managerToken string, err error)
	SwarmNodeList(ctx context.Context) ([]SwarmNodeInfo, error)
	SwarmNodeRemove(ctx context.Context, nodeID string, force bool) error
	SwarmServiceCreate(ctx context.Context, opts SwarmServiceCreateOptions) (string, error)
	SwarmServiceList(ctx context.Context) ([]SwarmServiceInfo, error)
	SwarmServiceGet(ctx context.Context, serviceID string) (*SwarmServiceInfo, error)
	SwarmServiceRemove(ctx context.Context, serviceID string) error
	SwarmServiceScale(ctx context.Context, serviceID string, replicas uint64) error
	SwarmServiceUpdate(ctx context.Context, serviceID string, opts SwarmServiceUpdateOptions) error
	SwarmTaskList(ctx context.Context, serviceID string) ([]SwarmTaskInfo, error)
}

// Verify that *Client implements ClientAPI at compile time.
var _ ClientAPI = (*Client)(nil)
