// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides command dispatching to remote agents.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// CommandDispatcher sends commands to agents and tracks responses.
type CommandDispatcher struct {
	server     *Server
	pending    map[string]*pendingCommand
	mu         sync.RWMutex
	log        *logger.Logger
}

// pendingCommand tracks a command awaiting response.
type pendingCommand struct {
	Command   *protocol.Command
	ResultCh  chan *protocol.CommandResult
	CreatedAt time.Time
	Timeout   time.Duration
}

// NewCommandDispatcher creates a new command dispatcher.
func NewCommandDispatcher(server *Server, log *logger.Logger) *CommandDispatcher {
	return &CommandDispatcher{
		server:  server,
		pending: make(map[string]*pendingCommand),
		log:     log.Named("cmd-dispatcher"),
	}
}

// SendCommand sends a command to an agent and waits for the response.
func (d *CommandDispatcher) SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error) {
	// Validate command
	if cmd.ID == "" {
		cmd.ID = uuid.New().String()
	}
	if cmd.CreatedAt.IsZero() {
		cmd.CreatedAt = time.Now().UTC()
	}
	if cmd.Timeout == 0 {
		cmd.Timeout = protocol.DefaultTimeout(cmd.Type)
	}

	// Get agent for host
	conn, ok := d.server.GetAgentByHost(hostID)
	if !ok {
		return nil, &protocol.ProtocolError{
			Code:    protocol.ErrCodeAgentUnavailable,
			Message: "no agent connected for host",
		}
	}

	// Create reply subject
	replySubject := fmt.Sprintf("%s%s", protocol.SubjectReplyPrefix, cmd.ID)
	cmd.ReplyTo = replySubject

	// Setup reply channel
	replyCh := make(chan *nats.Msg, 1)
	sub, err := d.server.natsClient.Conn().ChanSubscribe(replySubject, replyCh)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe for reply: %w", err)
	}
	defer sub.Unsubscribe()

	// Track pending command
	pending := &pendingCommand{
		Command:   cmd,
		ResultCh:  make(chan *protocol.CommandResult, 1),
		CreatedAt: time.Now(),
		Timeout:   cmd.Timeout,
	}
	d.mu.Lock()
	d.pending[cmd.ID] = pending
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, cmd.ID)
		d.mu.Unlock()
	}()

	// Serialize command
	cmdData, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	// Send command to agent
	subject := fmt.Sprintf("%s%s", protocol.SubjectCommandPrefix, conn.AgentID)
	if err := d.server.publisher.Publish(subject, cmdData); err != nil {
		return nil, fmt.Errorf("failed to publish command: %w", err)
	}

	d.log.Debug("Command sent",
		"command_id", cmd.ID,
		"type", cmd.Type,
		"agent_id", conn.AgentID,
		"timeout", cmd.Timeout,
	)

	// Wait for response with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, cmd.Timeout)
	defer cancel()

	select {
	case <-timeoutCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &protocol.CommandResult{
			CommandID:   cmd.ID,
			Status:      protocol.CommandStatusTimeout,
			CompletedAt: time.Now().UTC(),
			Error: &protocol.CommandError{
				Code:    protocol.ErrCodeCommandTimeout,
				Message: fmt.Sprintf("command timed out after %v", cmd.Timeout),
			},
		}, nil

	case msg := <-replyCh:
		var result protocol.CommandResult
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal result: %w", err)
		}

		d.log.Debug("Command result received",
			"command_id", cmd.ID,
			"status", result.Status,
			"duration", result.Duration,
		)

		return &result, nil
	}
}

// SendCommandAsync sends a command without waiting for response.
// The result will be delivered to the provided callback.
func (d *CommandDispatcher) SendCommandAsync(
	ctx context.Context,
	hostID uuid.UUID,
	cmd *protocol.Command,
	callback func(*protocol.CommandResult),
) error {
	// Validate command
	if cmd.ID == "" {
		cmd.ID = uuid.New().String()
	}
	if cmd.CreatedAt.IsZero() {
		cmd.CreatedAt = time.Now().UTC()
	}
	if cmd.Timeout == 0 {
		cmd.Timeout = protocol.DefaultTimeout(cmd.Type)
	}

	// Get agent for host
	conn, ok := d.server.GetAgentByHost(hostID)
	if !ok {
		return &protocol.ProtocolError{
			Code:    protocol.ErrCodeAgentUnavailable,
			Message: "no agent connected for host",
		}
	}

	// Create reply subject
	replySubject := fmt.Sprintf("%s%s", protocol.SubjectReplyPrefix, cmd.ID)
	cmd.ReplyTo = replySubject

	// Setup async reply handler
	sub, err := d.server.natsClient.Conn().Subscribe(replySubject, func(msg *nats.Msg) {
		var result protocol.CommandResult
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			d.log.Warn("Failed to unmarshal async result", "error", err)
			return
		}
		if callback != nil {
			callback(&result)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe for reply: %w", err)
	}

	// Auto-unsubscribe after timeout
	sub.AutoUnsubscribe(1)
	go func() {
		time.Sleep(cmd.Timeout + 5*time.Second)
		sub.Unsubscribe()
	}()

	// Serialize and send
	cmdData, err := json.Marshal(cmd)
	if err != nil {
		sub.Unsubscribe()
		return fmt.Errorf("failed to marshal command: %w", err)
	}

	subject := fmt.Sprintf("%s%s", protocol.SubjectCommandPrefix, conn.AgentID)
	if err := d.server.publisher.Publish(subject, cmdData); err != nil {
		sub.Unsubscribe()
		return fmt.Errorf("failed to publish command: %w", err)
	}

	d.log.Debug("Async command sent",
		"command_id", cmd.ID,
		"type", cmd.Type,
		"agent_id", conn.AgentID,
	)

	return nil
}

// BroadcastCommand sends a command to all connected agents.
func (d *CommandDispatcher) BroadcastCommand(ctx context.Context, cmd *protocol.Command) map[uuid.UUID]*protocol.CommandResult {
	agents := d.server.ListAgents()
	results := make(map[uuid.UUID]*protocol.CommandResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, agent := range agents {
		wg.Add(1)
		go func(conn *AgentConnection) {
			defer wg.Done()

			// Clone command for each agent
			agentCmd := *cmd
			agentCmd.ID = uuid.New().String()
			agentCmd.HostID = conn.HostID.String()

			result, err := d.SendCommand(ctx, conn.HostID, &agentCmd)
			if err != nil {
				result = &protocol.CommandResult{
					CommandID: agentCmd.ID,
					Status:    protocol.CommandStatusFailed,
					Error: &protocol.CommandError{
						Code:    protocol.ErrCodeCommandFailed,
						Message: err.Error(),
					},
				}
			}

			mu.Lock()
			results[conn.HostID] = result
			mu.Unlock()
		}(agent)
	}

	wg.Wait()
	return results
}

// PendingCount returns the number of pending commands.
func (d *CommandDispatcher) PendingCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.pending)
}

// ============================================================================
// Command Builder Helpers
// ============================================================================

// NewContainerCommand creates a container command.
func NewContainerCommand(cmdType protocol.CommandType, containerID string) *protocol.Command {
	return &protocol.Command{
		ID:        uuid.New().String(),
		Type:      cmdType,
		CreatedAt: time.Now().UTC(),
		Timeout:   protocol.DefaultTimeout(cmdType),
		Params: protocol.CommandParams{
			ContainerID: containerID,
		},
	}
}

// NewImageCommand creates an image command.
func NewImageCommand(cmdType protocol.CommandType, imageRef string) *protocol.Command {
	return &protocol.Command{
		ID:        uuid.New().String(),
		Type:      cmdType,
		CreatedAt: time.Now().UTC(),
		Timeout:   protocol.DefaultTimeout(cmdType),
		Params: protocol.CommandParams{
			ImageRef: imageRef,
		},
	}
}

// NewStackCommand creates a stack command.
func NewStackCommand(cmdType protocol.CommandType, stackName string, composeFile string) *protocol.Command {
	return &protocol.Command{
		ID:        uuid.New().String(),
		Type:      cmdType,
		CreatedAt: time.Now().UTC(),
		Timeout:   protocol.DefaultTimeout(cmdType),
		Params: protocol.CommandParams{
			StackName:   stackName,
			ComposeFile: composeFile,
		},
	}
}

// CommandBuilder provides a fluent API for building commands.
type CommandBuilder struct {
	cmd *protocol.Command
}

// NewCommandBuilder creates a new command builder.
func NewCommandBuilder(cmdType protocol.CommandType) *CommandBuilder {
	return &CommandBuilder{
		cmd: &protocol.Command{
			ID:        uuid.New().String(),
			Type:      cmdType,
			CreatedAt: time.Now().UTC(),
			Timeout:   protocol.DefaultTimeout(cmdType),
			Priority:  protocol.PriorityNormal,
			Params:    protocol.CommandParams{},
		},
	}
}

// WithContainer sets the container ID.
func (b *CommandBuilder) WithContainer(containerID string) *CommandBuilder {
	b.cmd.Params.ContainerID = containerID
	return b
}

// WithContainerName sets the container name.
func (b *CommandBuilder) WithContainerName(name string) *CommandBuilder {
	b.cmd.Params.ContainerName = name
	return b
}

// WithImage sets the image reference.
func (b *CommandBuilder) WithImage(imageRef string) *CommandBuilder {
	b.cmd.Params.ImageRef = imageRef
	return b
}

// WithStack sets the stack name and compose file.
func (b *CommandBuilder) WithStack(name, composeFile string) *CommandBuilder {
	b.cmd.Params.StackName = name
	b.cmd.Params.ComposeFile = composeFile
	return b
}

// WithVolume sets the volume name.
func (b *CommandBuilder) WithVolume(volumeName string) *CommandBuilder {
	b.cmd.Params.VolumeName = volumeName
	return b
}

// WithNetwork sets the network ID or name.
func (b *CommandBuilder) WithNetwork(networkID string) *CommandBuilder {
	b.cmd.Params.NetworkID = networkID
	return b
}

// WithTimeout sets a custom timeout.
func (b *CommandBuilder) WithTimeout(timeout time.Duration) *CommandBuilder {
	b.cmd.Timeout = timeout
	return b
}

// WithPriority sets the command priority.
func (b *CommandBuilder) WithPriority(priority protocol.CommandPriority) *CommandBuilder {
	b.cmd.Priority = priority
	return b
}

// WithForce sets the force flag.
func (b *CommandBuilder) WithForce() *CommandBuilder {
	b.cmd.Params.Force = true
	return b
}

// WithSignal sets the signal for kill/stop commands.
func (b *CommandBuilder) WithSignal(signal string) *CommandBuilder {
	b.cmd.Params.Signal = signal
	return b
}

// WithStopTimeout sets the stop timeout.
func (b *CommandBuilder) WithStopTimeout(timeout int) *CommandBuilder {
	b.cmd.Params.StopTimeout = &timeout
	return b
}

// WithEnvVars sets environment variables.
func (b *CommandBuilder) WithEnvVars(envVars map[string]string) *CommandBuilder {
	b.cmd.Params.EnvVars = envVars
	return b
}

// WithFilters sets filters for list operations.
func (b *CommandBuilder) WithFilters(filters map[string][]string) *CommandBuilder {
	b.cmd.Params.Filters = filters
	return b
}

// WithAll sets the all flag for list operations.
func (b *CommandBuilder) WithAll() *CommandBuilder {
	b.cmd.Params.All = true
	return b
}

// WithCreatedBy sets who created the command.
func (b *CommandBuilder) WithCreatedBy(userID string) *CommandBuilder {
	b.cmd.CreatedBy = userID
	return b
}

// Idempotent marks the command as safe to retry.
func (b *CommandBuilder) Idempotent() *CommandBuilder {
	b.cmd.Idempotent = true
	return b
}

// WithMaxRetries sets max retry attempts.
func (b *CommandBuilder) WithMaxRetries(n int) *CommandBuilder {
	b.cmd.MaxRetries = n
	return b
}

// Build returns the constructed command.
func (b *CommandBuilder) Build() *protocol.Command {
	return b.cmd
}

// ============================================================================
// Convenience Methods on Server
// ============================================================================

// SendCommand is a convenience method on Server for sending commands.
func (s *Server) SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error) {
	dispatcher := NewCommandDispatcher(s, s.log)
	return dispatcher.SendCommand(ctx, hostID, cmd)
}

// ExecuteContainerAction executes a container lifecycle action.
func (s *Server) ExecuteContainerAction(ctx context.Context, hostID uuid.UUID, containerID string, action protocol.CommandType) (*protocol.CommandResult, error) {
	cmd := NewCommandBuilder(action).
		WithContainer(containerID).
		Build()

	return s.SendCommand(ctx, hostID, cmd)
}

// PullImage pulls an image on a remote host.
func (s *Server) PullImage(ctx context.Context, hostID uuid.UUID, imageRef string) (*protocol.CommandResult, error) {
	cmd := NewCommandBuilder(protocol.CmdImagePull).
		WithImage(imageRef).
		Build()

	return s.SendCommand(ctx, hostID, cmd)
}

// DeployStack deploys a compose stack on a remote host.
func (s *Server) DeployStack(ctx context.Context, hostID uuid.UUID, stackName, composeContent string, envVars map[string]string) (*protocol.CommandResult, error) {
	cmd := NewCommandBuilder(protocol.CmdStackDeploy).
		WithStack(stackName, composeContent).
		WithEnvVars(envVars).
		Build()

	return s.SendCommand(ctx, hostID, cmd)
}

// GetSystemInfo retrieves system info from a remote host.
func (s *Server) GetSystemInfo(ctx context.Context, hostID uuid.UUID) (*protocol.CommandResult, error) {
	cmd := NewCommandBuilder(protocol.CmdSystemInfo).Build()
	return s.SendCommand(ctx, hostID, cmd)
}
