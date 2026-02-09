// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// CaptureRepository defines the interface for capture storage.
type CaptureRepository interface {
	Create(ctx context.Context, capture *models.PacketCapture) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.PacketCapture, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.PacketCapture, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.CaptureStatus, msg string) error
	UpdateStats(ctx context.Context, id uuid.UUID, packetCount int64, fileSize int64) error
	Stop(ctx context.Context, id uuid.UUID, packetCount int64, fileSize int64) error
	SetPID(ctx context.Context, id uuid.UUID, pid int) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// activeCapture tracks a running tcpdump process.
type activeCapture struct {
	ID          uuid.UUID
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	packetCount int64
	mu          sync.Mutex
}

// Service manages packet capture operations.
type Service struct {
	repo       CaptureRepository
	logger     *logger.Logger
	captureDir string

	mu       sync.RWMutex
	active   map[uuid.UUID]*activeCapture
	tcpdump  string // path to tcpdump binary
}

// NewService creates a new capture service.
func NewService(repo CaptureRepository, log *logger.Logger) *Service {
	// Find tcpdump binary
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		log.Warn("tcpdump not found in PATH, packet capture will be limited")
		tcpdumpPath = ""
	}

	// Create capture directory
	captureDir := "/tmp/usulnet/captures"
	os.MkdirAll(captureDir, 0750)

	return &Service{
		repo:       repo,
		logger:     log.Named("capture"),
		captureDir: captureDir,
		active:     make(map[uuid.UUID]*activeCapture),
		tcpdump:    tcpdumpPath,
	}
}

// Available returns whether tcpdump is available.
func (s *Service) Available() bool {
	return s.tcpdump != ""
}

// StartCapture creates a new capture and starts tcpdump.
func (s *Service) StartCapture(ctx context.Context, userID uuid.UUID, input models.CreateCaptureInput) (*models.PacketCapture, error) {
	if s.tcpdump == "" {
		return nil, errors.New(errors.CodeInternal, "tcpdump is not installed on this system")
	}

	// Create PCAP file path
	captureID := uuid.New()
	pcapFile := filepath.Join(s.captureDir, captureID.String()+".pcap")

	capture := &models.PacketCapture{
		UserID:      userID,
		Name:        input.Name,
		Interface:   input.Interface,
		Filter:      input.Filter,
		Status:      models.CaptureStatusRunning,
		MaxPackets:  input.MaxPackets,
		MaxDuration: input.MaxDuration,
		FilePath:    pcapFile,
	}

	if err := s.repo.Create(ctx, capture); err != nil {
		return nil, err
	}

	// Build tcpdump command
	args := []string{
		"-i", input.Interface,
		"-w", pcapFile,
		"-U", // Packet-buffered output
	}

	if input.MaxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(input.MaxPackets))
	}

	if input.Filter != "" {
		args = append(args, input.Filter)
	}

	// Create a cancellable context for the capture
	captureCtx, cancel := context.WithCancel(context.Background())

	// If max duration set, add timeout
	if input.MaxDuration > 0 {
		captureCtx, cancel = context.WithTimeout(context.Background(), time.Duration(input.MaxDuration)*time.Second)
	}

	cmd := exec.CommandContext(captureCtx, s.tcpdump, args...)

	// Capture stderr for packet count parsing
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		s.repo.UpdateStatus(ctx, capture.ID, models.CaptureStatusError, "failed to create stderr pipe")
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to setup capture process")
	}

	if err := cmd.Start(); err != nil {
		cancel()
		s.repo.UpdateStatus(ctx, capture.ID, models.CaptureStatusError, "failed to start tcpdump: "+err.Error())
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to start tcpdump")
	}

	// Store PID
	s.repo.SetPID(ctx, capture.ID, cmd.Process.Pid)
	capture.PID = cmd.Process.Pid

	ac := &activeCapture{
		ID:     capture.ID,
		cmd:    cmd,
		cancel: cancel,
	}

	s.mu.Lock()
	s.active[capture.ID] = ac
	s.mu.Unlock()

	s.logger.Info("packet capture started",
		"id", capture.ID,
		"interface", input.Interface,
		"filter", input.Filter,
		"pid", cmd.Process.Pid,
		"file", pcapFile,
	)

	// Monitor the capture in background
	go s.monitorCapture(ac, stderr, pcapFile)

	return capture, nil
}

// monitorCapture watches a running tcpdump process and updates stats.
func (s *Service) monitorCapture(ac *activeCapture, stderr io.ReadCloser, pcapFile string) {
	// Wait for process to complete
	scanner := bufio.NewScanner(stderr)
	var lastLine string
	for scanner.Scan() {
		lastLine = scanner.Text()
	}

	// Wait for the process
	err := ac.cmd.Wait()

	// Parse final packet count from tcpdump output
	// tcpdump prints something like: "123 packets captured"
	var packetCount int64
	if lastLine != "" {
		parts := strings.Fields(lastLine)
		if len(parts) >= 2 {
			if n, e := strconv.ParseInt(parts[0], 10, 64); e == nil {
				packetCount = n
			}
		}
	}

	// Get file size
	var fileSize int64
	if info, statErr := os.Stat(pcapFile); statErr == nil {
		fileSize = info.Size()
	}

	// Determine final status
	ctx := context.Background()
	status := models.CaptureStatusCompleted
	statusMsg := "Capture completed"
	if err != nil {
		if strings.Contains(err.Error(), "signal: killed") || strings.Contains(err.Error(), "signal: terminated") {
			status = models.CaptureStatusStopped
			statusMsg = "Capture stopped by user"
		} else if strings.Contains(err.Error(), "context") {
			status = models.CaptureStatusCompleted
			statusMsg = "Capture completed (duration limit reached)"
		} else {
			status = models.CaptureStatusError
			statusMsg = "tcpdump error: " + err.Error()
		}
	}

	s.repo.Stop(ctx, ac.ID, packetCount, fileSize)
	s.repo.UpdateStatus(ctx, ac.ID, status, statusMsg)

	s.mu.Lock()
	delete(s.active, ac.ID)
	s.mu.Unlock()

	s.logger.Info("packet capture finished",
		"id", ac.ID,
		"status", status,
		"packets", packetCount,
		"file_size", fileSize,
	)
}

// StopCapture stops a running capture.
func (s *Service) StopCapture(ctx context.Context, id uuid.UUID) error {
	s.mu.RLock()
	ac, exists := s.active[id]
	s.mu.RUnlock()

	if !exists {
		// Not actively running, just update status
		return s.repo.UpdateStatus(ctx, id, models.CaptureStatusStopped, "Capture stopped")
	}

	// Cancel the context which sends SIGKILL to the process
	ac.cancel()

	s.logger.Info("stopping packet capture", "id", id)
	return nil
}

// GetCapture retrieves a capture by ID.
func (s *Service) GetCapture(ctx context.Context, id uuid.UUID) (*models.PacketCapture, error) {
	capture, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update stats for running captures
	if capture.Status == models.CaptureStatusRunning {
		if info, statErr := os.Stat(capture.FilePath); statErr == nil {
			capture.FileSize = info.Size()
		}
	}

	return capture, nil
}

// ListCaptures retrieves all captures for a user.
func (s *Service) ListCaptures(ctx context.Context, userID uuid.UUID) ([]*models.PacketCapture, error) {
	captures, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Update stats for running captures
	for _, c := range captures {
		if c.Status == models.CaptureStatusRunning {
			if info, statErr := os.Stat(c.FilePath); statErr == nil {
				c.FileSize = info.Size()
			}
		}
	}

	return captures, nil
}

// DeleteCapture deletes a capture and its PCAP file.
func (s *Service) DeleteCapture(ctx context.Context, id uuid.UUID) error {
	// Stop if running
	s.mu.RLock()
	_, isRunning := s.active[id]
	s.mu.RUnlock()
	if isRunning {
		s.StopCapture(ctx, id)
		// Give it a moment to clean up
		time.Sleep(100 * time.Millisecond)
	}

	// Get capture to find file path
	capture, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete PCAP file
	if capture.FilePath != "" {
		os.Remove(capture.FilePath)
	}

	return s.repo.Delete(ctx, id)
}

// GetPcapPath returns the path to a capture's PCAP file.
func (s *Service) GetPcapPath(ctx context.Context, id uuid.UUID) (string, error) {
	capture, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", err
	}

	if capture.FilePath == "" {
		return "", errors.NotFound("PCAP file")
	}

	if _, err := os.Stat(capture.FilePath); os.IsNotExist(err) {
		return "", errors.NotFound("PCAP file")
	}

	return capture.FilePath, nil
}

// Cleanup stops all running captures. Called during shutdown.
func (s *Service) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, ac := range s.active {
		s.logger.Info("stopping capture on shutdown", "id", id)
		ac.cancel()
	}
}

// toCaptureSession converts a model to template data.
func ToCaptureSession(c *models.PacketCapture) CaptureSessionView {
	session := CaptureSessionView{
		ID:          c.ID.String(),
		Name:        c.Name,
		Interface:   c.Interface,
		Filter:      c.Filter,
		Status:      string(c.Status),
		PacketCount: c.PacketCount,
		Size:        c.FileSizeHuman(),
		StartedAt:   c.StartedAt.Format("2006-01-02 15:04:05"),
		PcapFile:    c.FilePath,
	}

	if c.StoppedAt != nil {
		session.StoppedAt = c.StoppedAt.Format("2006-01-02 15:04:05")
	}

	// Format duration
	d := c.Duration()
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	session.Duration = fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)

	return session
}

// CaptureSessionView is the template view data for a capture.
type CaptureSessionView struct {
	ID          string
	Name        string
	Interface   string
	Filter      string
	Status      string
	PacketCount int64
	Size        string
	Duration    string
	StartedAt   string
	StoppedAt   string
	PcapFile    string
}
