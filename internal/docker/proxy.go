// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// AgentProxyClient implements ClientAPI by routing Docker operations through
// the NATS gateway to remote agents, enabling transparent multi-host management.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/volume"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ErrNotSupportedRemote is returned for operations not available via remote agents.
var ErrNotSupportedRemote = errors.New("operation not supported for remote agents")

// RemoteError represents an error returned by a remote agent.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote agent error [%s]: %s", e.Code, e.Message)
}

// CommandSender sends commands to remote agents via the NATS gateway.
// *gateway.Server satisfies this interface.
type CommandSender interface {
	SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error)
}

// AgentProxyClient routes Docker operations through the NATS gateway to a remote agent.
type AgentProxyClient struct {
	sender CommandSender
	hostID uuid.UUID
	log    *logger.Logger
	closed bool
	mu     sync.RWMutex
}

// Compile-time interface verification.
var _ ClientAPI = (*AgentProxyClient)(nil)

// NewAgentProxyClient creates a proxy client for a remote agent host.
func NewAgentProxyClient(sender CommandSender, hostID uuid.UUID, log *logger.Logger) *AgentProxyClient {
	return &AgentProxyClient{
		sender: sender,
		hostID: hostID,
		log:    log.Named("proxy").With("host_id", hostID.String()),
	}
}

// HostID returns the host UUID this proxy targets.
func (p *AgentProxyClient) HostID() uuid.UUID {
	return p.hostID
}

// ============================================================================
// Internal helpers
// ============================================================================

// sendCmd builds a protocol.Command and dispatches it to the remote agent.
func (p *AgentProxyClient) sendCmd(ctx context.Context, cmdType protocol.CommandType, params protocol.CommandParams) (*protocol.CommandResult, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("proxy client is closed")
	}
	p.mu.RUnlock()

	cmd := &protocol.Command{
		Type:      cmdType,
		CreatedAt: time.Now().UTC(),
		Timeout:   protocol.DefaultTimeout(cmdType),
		Params:    params,
	}

	result, err := p.sender.SendCommand(ctx, p.hostID, cmd)
	if err != nil {
		return nil, fmt.Errorf("remote %s: %w", cmdType, err)
	}
	return result, nil
}

// checkResult verifies the command completed successfully.
func checkResult(result *protocol.CommandResult) error {
	if result.Status != protocol.CommandStatusCompleted {
		if result.Error != nil {
			return &RemoteError{Code: result.Error.Code, Message: result.Error.Message}
		}
		return fmt.Errorf("remote command status: %s", result.Status)
	}
	return nil
}

// decodeData unmarshals CommandResult.Data into the target type via JSON round-trip.
func decodeData[T any](result *protocol.CommandResult) (T, error) {
	var zero T
	if err := checkResult(result); err != nil {
		return zero, err
	}

	jsonBytes, err := json.Marshal(result.Data)
	if err != nil {
		return zero, fmt.Errorf("encode result data: %w", err)
	}

	var target T
	if err := json.Unmarshal(jsonBytes, &target); err != nil {
		return zero, fmt.Errorf("decode result data into %T: %w", target, err)
	}
	return target, nil
}

// parseRemoteLogLines splits buffered log text into LogLine entries.
func parseRemoteLogLines(logsStr string) []LogLine {
	var lines []LogLine
	for _, line := range strings.Split(logsStr, "\n") {
		if line == "" {
			continue
		}
		lines = append(lines, LogLine{
			Stream:  "stdout",
			Message: line,
		})
	}
	return lines
}

// ============================================================================
// System operations
// ============================================================================

func (p *AgentProxyClient) Ping(ctx context.Context) error {
	result, err := p.sendCmd(ctx, protocol.CmdSystemPing, protocol.CommandParams{})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) Info(ctx context.Context) (*DockerInfo, error) {
	result, err := p.sendCmd(ctx, protocol.CmdSystemInfo, protocol.CommandParams{})
	if err != nil {
		return nil, err
	}
	info, err := decodeData[DockerInfo](result)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (p *AgentProxyClient) ServerVersion(ctx context.Context) (string, error) {
	result, err := p.sendCmd(ctx, protocol.CmdSystemVersion, protocol.CommandParams{})
	if err != nil {
		return "", err
	}
	data, err := decodeData[map[string]string](result)
	if err != nil {
		return "", err
	}
	return data["version"], nil
}

func (p *AgentProxyClient) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func (p *AgentProxyClient) IsClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// ============================================================================
// Container lifecycle
// ============================================================================

func (p *AgentProxyClient) ContainerList(ctx context.Context, opts ContainerListOptions) ([]Container, error) {
	result, err := p.sendCmd(ctx, protocol.CmdContainerList, protocol.CommandParams{
		All:     opts.All,
		Limit:   opts.Limit,
		Filters: opts.Filters,
	})
	if err != nil {
		return nil, err
	}
	return decodeData[[]Container](result)
}

func (p *AgentProxyClient) ContainerGet(ctx context.Context, containerID string) (*ContainerDetails, error) {
	result, err := p.sendCmd(ctx, protocol.CmdContainerInspect, protocol.CommandParams{
		ContainerID: containerID,
	})
	if err != nil {
		return nil, err
	}
	details, err := decodeData[ContainerDetails](result)
	if err != nil {
		return nil, err
	}
	return &details, nil
}

func (p *AgentProxyClient) ContainerInspectRaw(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	return types.ContainerJSON{}, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerCreate(ctx context.Context, opts ContainerCreateOptions) (string, error) {
	result, err := p.sendCmd(ctx, protocol.CmdContainerCreate, protocol.CommandParams{
		ContainerName: opts.Name,
		Config:        opts,
	})
	if err != nil {
		return "", err
	}
	data, err := decodeData[map[string]string](result)
	if err != nil {
		return "", err
	}
	return data["container_id"], nil
}

func (p *AgentProxyClient) ContainerStart(ctx context.Context, containerID string) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerStart, protocol.CommandParams{
		ContainerID: containerID,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerStop(ctx context.Context, containerID string, timeout *int) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerStop, protocol.CommandParams{
		ContainerID: containerID,
		StopTimeout: timeout,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerRestart(ctx context.Context, containerID string, timeout *int) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerRestart, protocol.CommandParams{
		ContainerID: containerID,
		StopTimeout: timeout,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerKill(ctx context.Context, containerID string, signal string) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerKill, protocol.CommandParams{
		ContainerID: containerID,
		Signal:      signal,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerPause(ctx context.Context, containerID string) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerPause, protocol.CommandParams{
		ContainerID: containerID,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerUnpause(ctx context.Context, containerID string) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerUnpause, protocol.CommandParams{
		ContainerID: containerID,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerRename(ctx context.Context, containerID, newName string) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerRename, protocol.CommandParams{
		ContainerID:   containerID,
		ContainerName: newName,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerRemove(ctx context.Context, containerID string, force bool, removeVolumes bool) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerRemove, protocol.CommandParams{
		ContainerID:   containerID,
		Force:         force,
		RemoveVolumes: removeVolumes,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerUpdate(ctx context.Context, containerID string, resources Resources) error {
	result, err := p.sendCmd(ctx, protocol.CmdContainerUpdate, protocol.CommandParams{
		ContainerID: containerID,
		Config:      resources,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ContainerPrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error) {
	return 0, nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerTop(ctx context.Context, containerID string, psArgs string) ([][]string, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerWait(ctx context.Context, containerID string) (int64, error) {
	return 0, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerCommit(ctx context.Context, containerID string, options CommitOptions) (string, error) {
	return "", ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerCopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader) error {
	return ErrNotSupportedRemote
}

func (p *AgentProxyClient) ContainerCopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	return nil, container.PathStat{}, ErrNotSupportedRemote
}

func (p *AgentProxyClient) WaitForHealthy(ctx context.Context, containerID string, timeout time.Duration) error {
	return ErrNotSupportedRemote
}

// ============================================================================
// Image operations
// ============================================================================

func (p *AgentProxyClient) ImageList(ctx context.Context, opts ImageListOptions) ([]Image, error) {
	result, err := p.sendCmd(ctx, protocol.CmdImageList, protocol.CommandParams{
		All:     opts.All,
		Filters: opts.Filters,
	})
	if err != nil {
		return nil, err
	}
	return decodeData[[]Image](result)
}

func (p *AgentProxyClient) ImageGet(ctx context.Context, imageID string) (*ImageDetails, error) {
	result, err := p.sendCmd(ctx, protocol.CmdImageInspect, protocol.CommandParams{
		ImageRef: imageID,
	})
	if err != nil {
		return nil, err
	}
	details, err := decodeData[ImageDetails](result)
	if err != nil {
		return nil, err
	}
	return &details, nil
}

func (p *AgentProxyClient) ImagePull(ctx context.Context, ref string, opts ImagePullOptions) (<-chan PullProgress, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImagePullSync(ctx context.Context, ref string, opts ImagePullOptions) error {
	result, err := p.sendCmd(ctx, protocol.CmdImagePull, protocol.CommandParams{
		ImageRef: ref,
		Platform: opts.Platform,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ImagePush(ctx context.Context, ref string, registryAuth string) (<-chan PullProgress, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageRemove(ctx context.Context, imageID string, force bool, pruneChildren bool) ([]image.DeleteResponse, error) {
	result, err := p.sendCmd(ctx, protocol.CmdImageRemove, protocol.CommandParams{
		ImageRef: imageID,
		Force:    force,
	})
	if err != nil {
		return nil, err
	}
	if err := checkResult(result); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *AgentProxyClient) ImageTag(ctx context.Context, source, target string) error {
	result, err := p.sendCmd(ctx, protocol.CmdImageTag, protocol.CommandParams{
		ImageRef: source,
		Tag:      target,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) ImagePrune(ctx context.Context, dangling bool, pruneFilters map[string][]string) (uint64, []image.DeleteResponse, error) {
	result, err := p.sendCmd(ctx, protocol.CmdImagePrune, protocol.CommandParams{
		PruneAll:     !dangling,
		PruneFilters: pruneFilters,
	})
	if err != nil {
		return 0, nil, err
	}
	data, err := decodeData[map[string]interface{}](result)
	if err != nil {
		return 0, nil, err
	}
	var spaceReclaimed uint64
	if sr, ok := data["space_reclaimed"].(float64); ok {
		spaceReclaimed = uint64(sr)
	}
	return spaceReclaimed, nil, nil
}

func (p *AgentProxyClient) ImageHistory(ctx context.Context, imageID string) ([]image.HistoryResponseItem, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageLoad(ctx context.Context, input io.Reader, quiet bool) (image.LoadResponse, error) {
	return image.LoadResponse{}, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageSearch(ctx context.Context, term string, limit int, registryAuth string) ([]registry.SearchResult, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageImport(ctx context.Context, source image.ImportSource, ref string, changes []string) (io.ReadCloser, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageBuild(ctx context.Context, buildContext io.Reader, opts types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	return types.ImageBuildResponse{}, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := p.ImageGet(ctx, ref)
	if err != nil {
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *AgentProxyClient) ImageDigest(ctx context.Context, ref string) (string, error) {
	details, err := p.ImageGet(ctx, ref)
	if err != nil {
		return "", err
	}
	if len(details.RepoDigests) > 0 {
		return details.RepoDigests[0], nil
	}
	return "", nil
}

func (p *AgentProxyClient) ImageSize(ctx context.Context, ref string) (int64, error) {
	details, err := p.ImageGet(ctx, ref)
	if err != nil {
		return 0, err
	}
	return details.Size, nil
}

// ============================================================================
// Build cache operations
// ============================================================================

func (p *AgentProxyClient) BuildCachePrune(ctx context.Context, all bool) (int64, error) {
	result, err := p.sendCmd(ctx, protocol.CmdSystemPrune, protocol.CommandParams{
		PruneAll: all,
	})
	if err != nil {
		return 0, err
	}
	if result.Data != nil {
		if m, ok := result.Data.(map[string]interface{}); ok {
			if freed, ok := m["space_freed"].(float64); ok {
				return int64(freed), nil
			}
		}
	}
	return 0, nil
}

// ============================================================================
// Volume operations
// ============================================================================

func (p *AgentProxyClient) VolumeList(ctx context.Context, opts VolumeListOptions) ([]Volume, error) {
	result, err := p.sendCmd(ctx, protocol.CmdVolumeList, protocol.CommandParams{
		Filters: opts.Filters,
	})
	if err != nil {
		return nil, err
	}
	return decodeData[[]Volume](result)
}

func (p *AgentProxyClient) VolumeGet(ctx context.Context, volumeName string) (*Volume, error) {
	result, err := p.sendCmd(ctx, protocol.CmdVolumeInspect, protocol.CommandParams{
		VolumeName: volumeName,
	})
	if err != nil {
		return nil, err
	}
	vol, err := decodeData[Volume](result)
	if err != nil {
		return nil, err
	}
	return &vol, nil
}

func (p *AgentProxyClient) VolumeCreate(ctx context.Context, opts VolumeCreateOptions) (*Volume, error) {
	result, err := p.sendCmd(ctx, protocol.CmdVolumeCreate, protocol.CommandParams{
		VolumeName: opts.Name,
		Driver:     opts.Driver,
		DriverOpts: opts.DriverOpts,
	})
	if err != nil {
		return nil, err
	}
	vol, err := decodeData[Volume](result)
	if err != nil {
		return nil, err
	}
	return &vol, nil
}

func (p *AgentProxyClient) VolumeRemove(ctx context.Context, volumeName string, force bool) error {
	result, err := p.sendCmd(ctx, protocol.CmdVolumeRemove, protocol.CommandParams{
		VolumeName: volumeName,
		Force:      force,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) VolumePrune(ctx context.Context, pruneFilters map[string][]string) (uint64, []string, error) {
	result, err := p.sendCmd(ctx, protocol.CmdVolumePrune, protocol.CommandParams{
		PruneFilters: pruneFilters,
	})
	if err != nil {
		return 0, nil, err
	}
	data, err := decodeData[map[string]interface{}](result)
	if err != nil {
		return 0, nil, err
	}
	var spaceReclaimed uint64
	if sr, ok := data["space_reclaimed"].(float64); ok {
		spaceReclaimed = uint64(sr)
	}
	var volumesDeleted []string
	if vd, ok := data["volumes_deleted"].([]interface{}); ok {
		for _, v := range vd {
			if s, ok := v.(string); ok {
				volumesDeleted = append(volumesDeleted, s)
			}
		}
	}
	return spaceReclaimed, volumesDeleted, nil
}

func (p *AgentProxyClient) VolumeExists(ctx context.Context, volumeName string) (bool, error) {
	_, err := p.VolumeGet(ctx, volumeName)
	if err != nil {
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *AgentProxyClient) VolumeUpdate(ctx context.Context, volumeName string, version uint64, opts volume.UpdateOptions) error {
	return ErrNotSupportedRemote
}

func (p *AgentProxyClient) VolumeUsedBy(ctx context.Context, volumeName string) ([]string, error) {
	containers, err := p.ContainerList(ctx, ContainerListOptions{
		All:     true,
		Filters: map[string][]string{"volume": {volumeName}},
	})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func (p *AgentProxyClient) VolumeSize(ctx context.Context, volumeName string) (int64, error) {
	vol, err := p.VolumeGet(ctx, volumeName)
	if err != nil {
		return 0, err
	}
	if vol.UsageData != nil {
		return vol.UsageData.Size, nil
	}
	return -1, nil
}

// ============================================================================
// Network operations
// ============================================================================

func (p *AgentProxyClient) NetworkList(ctx context.Context, opts NetworkListOptions) ([]Network, error) {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkList, protocol.CommandParams{
		Filters: opts.Filters,
	})
	if err != nil {
		return nil, err
	}
	return decodeData[[]Network](result)
}

func (p *AgentProxyClient) NetworkGet(ctx context.Context, networkID string) (*Network, error) {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkInspect, protocol.CommandParams{
		NetworkID: networkID,
	})
	if err != nil {
		return nil, err
	}
	net, err := decodeData[Network](result)
	if err != nil {
		return nil, err
	}
	return &net, nil
}

func (p *AgentProxyClient) NetworkCreate(ctx context.Context, opts NetworkCreateOptions) (*Network, error) {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkCreate, protocol.CommandParams{
		NetworkName: opts.Name,
		Driver:      opts.Driver,
		Internal:    opts.Internal,
		Attachable:  opts.Attachable,
	})
	if err != nil {
		return nil, err
	}
	data, err := decodeData[map[string]interface{}](result)
	if err != nil {
		return nil, err
	}
	netID, _ := data["network_id"].(string)
	return &Network{
		ID:   netID,
		Name: opts.Name,
	}, nil
}

func (p *AgentProxyClient) NetworkRemove(ctx context.Context, networkID string) error {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkRemove, protocol.CommandParams{
		NetworkID: networkID,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) NetworkConnect(ctx context.Context, networkID string, opts NetworkConnectOptions) error {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkConnect, protocol.CommandParams{
		NetworkID:   networkID,
		ContainerID: opts.ContainerID,
		IPAddress:   opts.IPAddress,
		Aliases:     opts.Aliases,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	result, err := p.sendCmd(ctx, protocol.CmdNetworkDisconnect, protocol.CommandParams{
		NetworkID:   networkID,
		ContainerID: containerID,
		Force:       force,
	})
	if err != nil {
		return err
	}
	return checkResult(result)
}

func (p *AgentProxyClient) NetworkPrune(ctx context.Context, pruneFilters map[string][]string) ([]string, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) NetworkExists(ctx context.Context, networkID string) (bool, error) {
	_, err := p.NetworkGet(ctx, networkID)
	if err != nil {
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *AgentProxyClient) NetworkGetByName(ctx context.Context, name string) (*Network, error) {
	networks, err := p.NetworkList(ctx, NetworkListOptions{
		Filters: map[string][]string{"name": {name}},
	})
	if err != nil {
		return nil, err
	}
	for i := range networks {
		if networks[i].Name == name {
			return &networks[i], nil
		}
	}
	return nil, fmt.Errorf("network %q not found", name)
}

func (p *AgentProxyClient) NetworkTopology(ctx context.Context) (map[string][]string, error) {
	return nil, ErrNotSupportedRemote
}

// ============================================================================
// Exec operations
// ============================================================================

func (p *AgentProxyClient) ContainerExec(ctx context.Context, containerID string, cmd []string, opts ExecOptions) (*ExecResult, error) {
	result, err := p.sendCmd(ctx, protocol.CmdExecRun, protocol.CommandParams{
		ContainerID:  containerID,
		Cmd:          cmd,
		Env:          opts.Env,
		WorkingDir:   opts.WorkingDir,
		User:         opts.User,
		Tty:          opts.Tty,
		Privileged:   opts.Privileged,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, err
	}
	execResult, err := decodeData[ExecResult](result)
	if err != nil {
		return nil, err
	}
	return &execResult, nil
}

func (p *AgentProxyClient) RunCommand(ctx context.Context, containerID string, cmd []string) (string, int, error) {
	result, err := p.ContainerExec(ctx, containerID, cmd, ExecOptions{})
	if err != nil {
		return "", -1, err
	}
	return result.Stdout, result.ExitCode, nil
}

func (p *AgentProxyClient) RunShellCommand(ctx context.Context, containerID string, command string) (string, int, error) {
	return p.RunCommand(ctx, containerID, []string{"sh", "-c", command})
}

func (p *AgentProxyClient) ExecCreate(ctx context.Context, containerID string, config ExecConfig) (*ExecCreateResponse, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ExecAttach(ctx context.Context, execID string) (types.HijackedResponse, error) {
	return types.HijackedResponse{}, ErrNotSupportedRemote
}

func (p *AgentProxyClient) ExecInspectByID(ctx context.Context, execID string) (*ExecInspect, error) {
	return nil, ErrNotSupportedRemote
}

// ============================================================================
// Log operations
// ============================================================================

func (p *AgentProxyClient) ContainerLogs(ctx context.Context, containerID string, opts LogOptions) (io.ReadCloser, error) {
	logsStr, err := p.ContainerLogsString(ctx, containerID, opts)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(logsStr)), nil
}

func (p *AgentProxyClient) ContainerLogsString(ctx context.Context, containerID string, opts LogOptions) (string, error) {
	result, err := p.sendCmd(ctx, protocol.CmdContainerLogs, protocol.CommandParams{
		ContainerID: containerID,
		Follow:      false, // Never follow for remote — buffered only
		Tail:        opts.Tail,
		Since:       opts.Since,
		Until:       opts.Until,
		Timestamps:  opts.Timestamps,
	})
	if err != nil {
		return "", err
	}
	data, err := decodeData[map[string]interface{}](result)
	if err != nil {
		return "", err
	}
	logs, _ := data["logs"].(string)
	return logs, nil
}

func (p *AgentProxyClient) ContainerLogsLines(ctx context.Context, containerID string, lines int) ([]LogLine, error) {
	logsStr, err := p.ContainerLogsString(ctx, containerID, LogOptions{
		Tail: fmt.Sprintf("%d", lines),
	})
	if err != nil {
		return nil, err
	}
	return parseRemoteLogLines(logsStr), nil
}

func (p *AgentProxyClient) ContainerLogsSince(ctx context.Context, containerID string, since time.Time) ([]LogLine, error) {
	logsStr, err := p.ContainerLogsString(ctx, containerID, LogOptions{
		Since: since.Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	return parseRemoteLogLines(logsStr), nil
}

// ============================================================================
// Stats operations
// ============================================================================

func (p *AgentProxyClient) ContainerStatsOnce(ctx context.Context, containerID string) (*ContainerStats, error) {
	result, err := p.sendCmd(ctx, protocol.CmdContainerStats, protocol.CommandParams{
		ContainerID: containerID,
	})
	if err != nil {
		return nil, err
	}
	stats, err := decodeData[ContainerStats](result)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

func (p *AgentProxyClient) MultiContainerStats(ctx context.Context, containerIDs []string) (map[string]*ContainerStats, error) {
	result := make(map[string]*ContainerStats)
	for _, id := range containerIDs {
		stats, err := p.ContainerStatsOnce(ctx, id)
		if err != nil {
			p.log.Warn("Failed to get remote stats", "container_id", id, "error", err)
			continue
		}
		result[id] = stats
	}
	return result, nil
}

func (p *AgentProxyClient) AllContainerStats(ctx context.Context) (map[string]*ContainerStats, error) {
	containers, err := p.ContainerList(ctx, ContainerListOptions{
		Filters: map[string][]string{"status": {"running"}},
	})
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(containers))
	for i, c := range containers {
		ids[i] = c.ID
	}
	return p.MultiContainerStats(ctx, ids)
}

// ============================================================================
// Swarm operations (proxy stubs - Swarm is managed on the master node directly)
// ============================================================================
//
// Architecture decision (DEPT-05-T05):
// Swarm operations are inherently cluster-level management tasks that MUST
// execute on the Swarm manager node. The AgentProxyClient operates on individual
// Docker hosts (agents), not on the Swarm control plane. Proxying these operations
// to remote agents would be architecturally incorrect because:
//
//   - SwarmInit/Join/Leave alter cluster membership (manager-only)
//   - SwarmInspect reads cluster-wide state (available only on managers)
//   - Service CRUD operates on the Swarm scheduler (manager-only)
//   - Node operations manage cluster membership (manager-only)
//
// All Swarm operations are handled directly on the master node via the local
// Docker client (LocalClient), which has direct access to the Swarm manager.
// The proxy layer correctly returns errSwarmNotProxied for all Swarm methods,
// guiding callers to use the master node directly.
//
// ============================================================================

var errSwarmNotProxied = fmt.Errorf("Swarm operations are not proxied to agents; use the master node directly")

func (p *AgentProxyClient) SwarmInit(_ context.Context, _, _ string, _ bool) (string, error) {
	return "", errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmJoin(_ context.Context, _, _, _ string) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmLeave(_ context.Context, _ bool) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmInspect(_ context.Context) (*SwarmClusterState, error) {
	return nil, errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmGetJoinTokens(_ context.Context) (string, string, error) {
	return "", "", errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmNodeList(_ context.Context) ([]SwarmNodeInfo, error) {
	return nil, errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmNodeRemove(_ context.Context, _ string, _ bool) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceCreate(_ context.Context, _ SwarmServiceCreateOptions) (string, error) {
	return "", errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceList(_ context.Context) ([]SwarmServiceInfo, error) {
	return nil, errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceGet(_ context.Context, _ string) (*SwarmServiceInfo, error) {
	return nil, errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceRemove(_ context.Context, _ string) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceScale(_ context.Context, _ string, _ uint64) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmServiceUpdate(_ context.Context, _ string, _ SwarmServiceUpdateOptions) error {
	return errSwarmNotProxied
}
func (p *AgentProxyClient) SwarmTaskList(_ context.Context, _ string) ([]SwarmTaskInfo, error) {
	return nil, errSwarmNotProxied
}

// ============================================================================
// Event operations (remote agents deliver events via NATS, not through proxy)
// ============================================================================

func (p *AgentProxyClient) GetEvents(_ context.Context, _ time.Time) ([]DockerEvent, error) {
	return nil, ErrNotSupportedRemote
}

func (p *AgentProxyClient) StreamEvents(_ context.Context) (<-chan DockerEvent, <-chan error) {
	ch := make(chan DockerEvent)
	close(ch)
	errCh := make(chan error, 1)
	errCh <- ErrNotSupportedRemote
	return ch, errCh
}
