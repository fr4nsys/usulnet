// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// LogOptions specifies options for retrieving container logs
type LogOptions struct {
	// Follow keeps the connection open and streams new logs
	Follow bool

	// Timestamps includes timestamps in the output
	Timestamps bool

	// Tail specifies the number of lines to show ("all" or a number)
	Tail string

	// Since shows logs since this time (RFC3339 or Unix timestamp)
	Since string

	// Until shows logs until this time (RFC3339 or Unix timestamp)
	Until string

	// Stdout includes stdout output
	Stdout bool

	// Stderr includes stderr output
	Stderr bool
}

// DefaultLogOptions returns sensible default log options
func DefaultLogOptions() LogOptions {
	return LogOptions{
		Follow:     false,
		Timestamps: true,
		Tail:       "100",
		Stdout:     true,
		Stderr:     true,
	}
}

// ContainerLogs returns a reader for container logs
// The caller is responsible for closing the returned reader
func (c *Client) ContainerLogs(ctx context.Context, containerID string, opts LogOptions) (io.ReadCloser, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	logsOpts := container.LogsOptions{
		ShowStdout: opts.Stdout,
		ShowStderr: opts.Stderr,
		Follow:     opts.Follow,
		Timestamps: opts.Timestamps,
	}

	if opts.Tail != "" {
		logsOpts.Tail = opts.Tail
	} else {
		logsOpts.Tail = "100"
	}

	if opts.Since != "" {
		logsOpts.Since = opts.Since
	}

	if opts.Until != "" {
		logsOpts.Until = opts.Until
	}

	reader, err := c.cli.ContainerLogs(ctx, containerID, logsOpts)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeContainerNotFound, "container not found").
				WithDetail("container_id", containerID)
		}
		log.Error("Failed to get container logs", "container_id", containerID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get container logs")
	}

	return reader, nil
}

// ContainerLogsString returns container logs as a string
// Useful for getting a snapshot of logs without streaming
func (c *Client) ContainerLogsString(ctx context.Context, containerID string, opts LogOptions) (string, error) {
	opts.Follow = false // Disable follow for string output

	reader, err := c.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	// Check if container uses TTY (no multiplexing)
	details, err := c.ContainerGet(ctx, containerID)
	if err != nil {
		return "", err
	}

	var stdout, stderr strings.Builder

	if details.Config != nil && details.Config.Tty {
		// TTY mode: no multiplexing, just read directly
		data, err := io.ReadAll(reader)
		if err != nil {
			return "", errors.Wrap(err, errors.CodeInternal, "failed to read logs")
		}
		return string(data), nil
	}

	// Non-TTY mode: demultiplex stdout/stderr
	if _, err := stdcopy.StdCopy(&stdout, &stderr, reader); err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to demultiplex logs")
	}

	// Combine stdout and stderr
	result := stdout.String()
	if stderr.Len() > 0 {
		if result != "" {
			result += "\n"
		}
		result += stderr.String()
	}

	return result, nil
}

// ContainerLogsStream streams container logs line by line
// Returns a channel of LogLine that the caller should consume
// The channel is closed when the stream ends or context is cancelled
func (c *Client) ContainerLogsStream(ctx context.Context, containerID string, opts LogOptions) (<-chan LogLine, error) {
	log := logger.FromContext(ctx)

	// Force follow mode for streaming
	opts.Follow = true
	if !opts.Stdout && !opts.Stderr {
		opts.Stdout = true
		opts.Stderr = true
	}

	reader, err := c.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, err
	}

	// Check if container uses TTY
	details, err := c.ContainerGet(ctx, containerID)
	if err != nil {
		reader.Close()
		return nil, err
	}

	isTTY := details.Config != nil && details.Config.Tty

	logCh := make(chan LogLine, 100)

	go func() {
		defer close(logCh)
		defer reader.Close()

		if isTTY {
			// TTY mode: no multiplexing, simple line reading
			c.streamTTYLogs(ctx, reader, logCh, opts.Timestamps, log)
		} else {
			// Non-TTY mode: multiplexed stdout/stderr with 8-byte header
			c.streamMultiplexedLogs(ctx, reader, logCh, opts.Timestamps, log)
		}
	}()

	return logCh, nil
}

// streamTTYLogs reads logs from a TTY container (no multiplexing)
func (c *Client) streamTTYLogs(ctx context.Context, reader io.Reader, logCh chan<- LogLine, hasTimestamps bool, log *logger.Logger) {
	scanner := bufio.NewScanner(reader)
	// Increase buffer size for long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		logLine := parseLogLine(line, "stdout", hasTimestamps)
		
		select {
		case logCh <- logLine:
		case <-ctx.Done():
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Debug("Log stream ended", "error", err)
	}
}

// streamMultiplexedLogs reads multiplexed logs (stdout/stderr with 8-byte header)
// Header format: [STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4]
// STREAM_TYPE: 1 = stdout, 2 = stderr
func (c *Client) streamMultiplexedLogs(ctx context.Context, reader io.Reader, logCh chan<- LogLine, hasTimestamps bool, log *logger.Logger) {
	header := make([]byte, 8)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read header
		_, err := io.ReadFull(reader, header)
		if err != nil {
			if err != io.EOF {
				log.Debug("Log stream ended", "error", err)
			}
			return
		}

		// Parse stream type
		stream := "stdout"
		if header[0] == 2 {
			stream = "stderr"
		}

		// Parse message size (big-endian uint32)
		size := binary.BigEndian.Uint32(header[4:8])

		// Read message
		message := make([]byte, size)
		_, err = io.ReadFull(reader, message)
		if err != nil {
			if err != io.EOF {
				log.Debug("Failed to read log message", "error", err)
			}
			return
		}

		// Parse the message (may contain timestamp)
		line := string(message)
		// Remove trailing newline if present
		line = strings.TrimSuffix(line, "\n")

		logLine := parseLogLine(line, stream, hasTimestamps)

		select {
		case logCh <- logLine:
		case <-ctx.Done():
			return
		}
	}
}

// parseLogLine parses a log line, extracting timestamp if present
func parseLogLine(line, stream string, hasTimestamps bool) LogLine {
	logLine := LogLine{
		Stream:    stream,
		Timestamp: time.Now(),
		Message:   line,
	}

	if hasTimestamps && len(line) > 30 {
		// Docker timestamps are in RFC3339Nano format: 2006-01-02T15:04:05.999999999Z
		// They are followed by a space and then the message
		spaceIdx := strings.Index(line, " ")
		if spaceIdx > 0 && spaceIdx < 35 {
			timeStr := line[:spaceIdx]
			if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
				logLine.Timestamp = t
				logLine.Message = line[spaceIdx+1:]
			}
		}
	}

	return logLine
}

// ContainerLogsLines returns the last N lines of container logs
func (c *Client) ContainerLogsLines(ctx context.Context, containerID string, lines int) ([]LogLine, error) {
	opts := LogOptions{
		Tail:       string(rune(lines)),
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
	}

	reader, err := c.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Check if container uses TTY
	details, err := c.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, err
	}

	isTTY := details.Config != nil && details.Config.Tty

	var result []LogLine

	if isTTY {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := parseLogLine(scanner.Text(), "stdout", true)
			result = append(result, line)
		}
	} else {
		// Demultiplex
		header := make([]byte, 8)
		for {
			_, err := io.ReadFull(reader, header)
			if err != nil {
				break
			}

			stream := "stdout"
			if header[0] == 2 {
				stream = "stderr"
			}

			size := binary.BigEndian.Uint32(header[4:8])
			message := make([]byte, size)

			_, err = io.ReadFull(reader, message)
			if err != nil {
				break
			}

			line := strings.TrimSuffix(string(message), "\n")
			logLine := parseLogLine(line, stream, true)
			result = append(result, logLine)
		}
	}

	return result, nil
}

// ContainerLogsSince returns logs since a specific time
func (c *Client) ContainerLogsSince(ctx context.Context, containerID string, since time.Time) ([]LogLine, error) {
	opts := LogOptions{
		Since:      since.Format(time.RFC3339),
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
	}

	reader, err := c.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Check if container uses TTY
	details, err := c.ContainerGet(ctx, containerID)
	if err != nil {
		return nil, err
	}

	isTTY := details.Config != nil && details.Config.Tty

	var result []LogLine

	if isTTY {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := parseLogLine(scanner.Text(), "stdout", true)
			result = append(result, line)
		}
	} else {
		header := make([]byte, 8)
		for {
			_, err := io.ReadFull(reader, header)
			if err != nil {
				break
			}

			stream := "stdout"
			if header[0] == 2 {
				stream = "stderr"
			}

			size := binary.BigEndian.Uint32(header[4:8])
			message := make([]byte, size)

			_, err = io.ReadFull(reader, message)
			if err != nil {
				break
			}

			line := strings.TrimSuffix(string(message), "\n")
			logLine := parseLogLine(line, stream, true)
			result = append(result, logLine)
		}
	}

	return result, nil
}

// LogWriter wraps a container log stream for writing
// Useful for forwarding logs to external systems
type LogWriter struct {
	containerID string
	stream      <-chan LogLine
	cancel      context.CancelFunc
}

// NewLogWriter creates a new log writer for a container
func (c *Client) NewLogWriter(ctx context.Context, containerID string) (*LogWriter, error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := c.ContainerLogsStream(ctx, containerID, LogOptions{
		Follow:     true,
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
		Tail:       "0", // Don't include history
	})
	if err != nil {
		cancel()
		return nil, err
	}

	return &LogWriter{
		containerID: containerID,
		stream:      stream,
		cancel:      cancel,
	}, nil
}

// Stream returns the channel of log lines
func (w *LogWriter) Stream() <-chan LogLine {
	return w.stream
}

// Close stops the log stream
func (w *LogWriter) Close() {
	w.cancel()
}

// ContainerID returns the container ID this writer is attached to
func (w *LogWriter) ContainerID() string {
	return w.containerID
}
