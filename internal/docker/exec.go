// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ExecOptions specifies options for executing commands in containers
type ExecOptions struct {
	// User specifies the user to run the command as
	User string

	// Privileged enables privileged mode
	Privileged bool

	// Env specifies environment variables
	Env []string

	// WorkingDir specifies the working directory
	WorkingDir string

	// Tty allocates a pseudo-TTY
	Tty bool

	// AttachStdin attaches stdin
	AttachStdin bool

	// Detach runs the command in the background
	Detach bool
}

// DefaultExecOptions returns default exec options
func DefaultExecOptions() ExecOptions {
	return ExecOptions{
		Tty:         false,
		AttachStdin: false,
		Detach:      false,
	}
}

// ContainerExec executes a command in a container and returns the result
func (c *Client) ContainerExec(ctx context.Context, containerID string, cmd []string, opts ExecOptions) (*ExecResult, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Create exec configuration
	execConfig := container.ExecOptions{
		User:         opts.User,
		Privileged:   opts.Privileged,
		Env:          opts.Env,
		WorkingDir:   opts.WorkingDir,
		Tty:          opts.Tty,
		AttachStdin:  opts.AttachStdin,
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}

	// Create exec instance
	execID, err := c.cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to create exec", "container_id", containerID, "cmd", cmd, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create exec")
	}

	// Attach to exec
	resp, err := c.cli.ContainerExecAttach(ctx, execID.ID, container.ExecStartOptions{
		Tty: opts.Tty,
	})
	if err != nil {
		log.Error("Failed to attach to exec", "exec_id", execID.ID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to attach to exec")
	}
	defer resp.Close()

	// Read output
	var stdout, stderr bytes.Buffer

	if opts.Tty {
		// TTY mode: no multiplexing, read directly
		io.Copy(&stdout, resp.Reader)
	} else {
		// Demultiplex stdout/stderr
		_, err = stdcopy.StdCopy(&stdout, &stderr, resp.Reader)
		if err != nil {
			log.Error("Failed to read exec output", "exec_id", execID.ID, "error", err)
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to read exec output")
		}
	}

	// Get exit code
	inspect, err := c.cli.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		log.Error("Failed to inspect exec", "exec_id", execID.ID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect exec")
	}

	return &ExecResult{
		ExitCode: inspect.ExitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

// ContainerExecDetached executes a command in a container without waiting for output
func (c *Client) ContainerExecDetached(ctx context.Context, containerID string, cmd []string, opts ExecOptions) (string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Create exec configuration
	execConfig := container.ExecOptions{
		User:         opts.User,
		Privileged:   opts.Privileged,
		Env:          opts.Env,
		WorkingDir:   opts.WorkingDir,
		Tty:          opts.Tty,
		Detach:       true,
		AttachStdin:  false,
		AttachStdout: false,
		AttachStderr: false,
		Cmd:          cmd,
	}

	// Create exec instance
	execID, err := c.cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "", errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to create exec", "container_id", containerID, "cmd", cmd, "error", err)
		return "", errors.Wrap(err, errors.CodeInternal, "failed to create exec")
	}

	// Start exec in detached mode
	if err := c.cli.ContainerExecStart(ctx, execID.ID, container.ExecStartOptions{
		Detach: true,
	}); err != nil {
		log.Error("Failed to start exec", "exec_id", execID.ID, "error", err)
		return "", errors.Wrap(err, errors.CodeInternal, "failed to start exec")
	}

	log.Debug("Exec started in detached mode", "exec_id", execID.ID, "container_id", containerID)
	return execID.ID, nil
}

// ContainerExecInteractive starts an interactive exec session
// Returns a HijackedResponse for bidirectional communication
// The caller is responsible for closing the response
func (c *Client) ContainerExecInteractive(ctx context.Context, containerID string, cmd []string, opts ExecOptions) (types.HijackedResponse, string, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return types.HijackedResponse{}, "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Force TTY and stdin for interactive mode
	opts.Tty = true
	opts.AttachStdin = true

	execConfig := container.ExecOptions{
		User:         opts.User,
		Privileged:   opts.Privileged,
		Env:          opts.Env,
		WorkingDir:   opts.WorkingDir,
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}

	// Create exec instance
	execID, err := c.cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		if client.IsErrNotFound(err) {
			return types.HijackedResponse{}, "", errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to create interactive exec", "container_id", containerID, "error", err)
		return types.HijackedResponse{}, "", errors.Wrap(err, errors.CodeInternal, "failed to create exec")
	}

	// Attach to exec
	resp, err := c.cli.ContainerExecAttach(ctx, execID.ID, container.ExecStartOptions{
		Tty: true,
	})
	if err != nil {
		log.Error("Failed to attach to interactive exec", "exec_id", execID.ID, "error", err)
		return types.HijackedResponse{}, "", errors.Wrap(err, errors.CodeInternal, "failed to attach to exec")
	}

	log.Debug("Interactive exec session started", "exec_id", execID.ID, "container_id", containerID)
	return resp, execID.ID, nil
}

// ContainerExecResize resizes the TTY of an exec process
func (c *Client) ContainerExecResize(ctx context.Context, execID string, height, width uint) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	err := c.cli.ContainerExecResize(ctx, execID, container.ResizeOptions{
		Height: height,
		Width:  width,
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to resize exec TTY")
	}

	return nil
}

// ContainerExecInspect returns information about an exec instance
func (c *Client) ContainerExecInspect(ctx context.Context, execID string) (*ExecInspect, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, err := c.cli.ContainerExecInspect(ctx, execID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect exec")
	}

	return &ExecInspect{
		ID:          inspect.ExecID,
		ContainerID: inspect.ContainerID,
		Running:     inspect.Running,
		ExitCode:    inspect.ExitCode,
		Pid:         inspect.Pid,
	}, nil
}

// ExecInspect contains information about an exec instance
type ExecInspect struct {
	ID          string
	ContainerID string
	Running     bool
	ExitCode    int
	Pid         int
}

// RunCommand is a convenience function to run a simple command and get the output
func (c *Client) RunCommand(ctx context.Context, containerID string, cmd []string) (string, int, error) {
	result, err := c.ContainerExec(ctx, containerID, cmd, DefaultExecOptions())
	if err != nil {
		return "", -1, err
	}

	output := result.Stdout
	if result.Stderr != "" {
		if output != "" {
			output += "\n"
		}
		output += result.Stderr
	}

	return output, result.ExitCode, nil
}

// RunShellCommand runs a command through /bin/sh
func (c *Client) RunShellCommand(ctx context.Context, containerID string, command string) (string, int, error) {
	return c.RunCommand(ctx, containerID, []string{"/bin/sh", "-c", command})
}

// RunBashCommand runs a command through /bin/bash
func (c *Client) RunBashCommand(ctx context.Context, containerID string, command string) (string, int, error) {
	return c.RunCommand(ctx, containerID, []string{"/bin/bash", "-c", command})
}

// CheckCommandExists checks if a command exists in the container
func (c *Client) CheckCommandExists(ctx context.Context, containerID, command string) (bool, error) {
	_, exitCode, err := c.RunShellCommand(ctx, containerID, "command -v "+command)
	if err != nil {
		// Check if it's a "command not found" error vs actual error
		if exitCode == 127 || exitCode == 1 {
			return false, nil
		}
		return false, err
	}
	return exitCode == 0, nil
}

// GetContainerEnv retrieves environment variables from a running container
func (c *Client) GetContainerEnv(ctx context.Context, containerID string) (map[string]string, error) {
	output, exitCode, err := c.RunShellCommand(ctx, containerID, "env")
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		return nil, errors.New(errors.CodeInternal, "failed to get environment variables")
	}

	env := make(map[string]string)
	for _, line := range bytes.Split([]byte(output), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte("="), 2)
		if len(parts) == 2 {
			env[string(parts[0])] = string(parts[1])
		}
	}

	return env, nil
}

// GetContainerWorkingDir retrieves the current working directory of a container
func (c *Client) GetContainerWorkingDir(ctx context.Context, containerID string) (string, error) {
	output, exitCode, err := c.RunShellCommand(ctx, containerID, "pwd")
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", errors.New(errors.CodeInternal, "failed to get working directory")
	}

	return strings.TrimSpace(output), nil
}

// ExecConfig specifies options for creating an exec instance
type ExecConfig struct {
	User         string
	Privileged   bool
	Tty          bool
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	Detach       bool
	DetachKeys   string
	Env          []string
	WorkingDir   string
	Cmd          []string
}

// ExecCreateResponse contains the response from creating an exec instance
type ExecCreateResponse struct {
	ID string
}

// ExecCreate creates an exec instance in a container
func (c *Client) ExecCreate(ctx context.Context, containerID string, config ExecConfig) (*ExecCreateResponse, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	execConfig := container.ExecOptions{
		User:         config.User,
		Privileged:   config.Privileged,
		Tty:          config.Tty,
		AttachStdin:  config.AttachStdin,
		AttachStdout: config.AttachStdout,
		AttachStderr: config.AttachStderr,
		Detach:       config.Detach,
		DetachKeys:   config.DetachKeys,
		Env:          config.Env,
		WorkingDir:   config.WorkingDir,
		Cmd:          config.Cmd,
	}

	resp, err := c.cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		log.Error("Failed to create exec", "container_id", containerID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create exec")
	}

	return &ExecCreateResponse{ID: resp.ID}, nil
}

// ExecAttach attaches to an exec instance and returns the hijacked connection.
// The caller is responsible for closing the returned HijackedResponse.
func (c *Client) ExecAttach(ctx context.Context, execID string) (types.HijackedResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return types.HijackedResponse{}, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ContainerExecAttach(ctx, execID, container.ExecAttachOptions{})
	if err != nil {
		return types.HijackedResponse{}, errors.Wrap(err, errors.CodeInternal, "failed to attach to exec")
	}

	return resp, nil
}

// ExecInspectByID inspects an exec instance by ID.
func (c *Client) ExecInspectByID(ctx context.Context, execID string) (*ExecInspect, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ContainerExecInspect(ctx, execID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect exec")
	}

	return &ExecInspect{
		ID:          resp.ExecID,
		ContainerID: resp.ContainerID,
		Running:     resp.Running,
		ExitCode:    resp.ExitCode,
		Pid:         resp.Pid,
	}, nil
}
