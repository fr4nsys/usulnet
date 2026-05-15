// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package crontab provides a managed cron job service for usulnet.
//
// Users create cron entries via the web UI or REST API; the service
// schedules and executes them in-process using robfig/cron/v3 and
// records execution history in PostgreSQL.
//
// The service is a free AGPL feature — no biz gating, no edition checks,
// no call-home. It executes user-supplied commands locally via os/exec
// with explicit argv slices: the shell command type intentionally
// invokes `sh -c <script>` so users can write shell pipelines, but the
// docker and http types never reach a shell parser.
//
// Cron parsing uses the standard 5-field expression via cron.ParseStandard.
// This is the only cron parser in the package — there is no second one.
package crontab

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors returned by the service. API and web handlers map
// these to stable HTTP status codes.
var (
	// ErrInvalidSchedule is returned when the supplied cron expression
	// does not parse against the standard 5-field grammar.
	ErrInvalidSchedule = stderrors.New("crontab: invalid schedule")

	// ErrInvalidInput is returned when a required field is missing or
	// malformed (e.g. empty name, unknown command_type).
	ErrInvalidInput = stderrors.New("crontab: invalid input")
)

const (
	// MaxOutputBytes caps the captured command output stored in the DB.
	// Anything larger is truncated. 10 KiB lines up with the v26.2.7
	// cap and keeps the executions table compact under tight loops.
	MaxOutputBytes = 10000

	// HTTPRequestTimeout caps the duration of HTTP-type cron jobs.
	HTTPRequestTimeout = 30 * time.Second

	// HTTPMaxBodyBytes caps the captured HTTP response body. Bodies
	// larger than this are truncated and the captured output reflects
	// the truncation in the trailing "...(truncated)" suffix.
	HTTPMaxBodyBytes = 64 * 1024

	// DefaultExecutionRetentionDays is the default age beyond which
	// the cleanup worker removes old execution rows.
	DefaultExecutionRetentionDays = 30

	// CleanupInterval is the gap between successive cleanup passes.
	CleanupInterval = 24 * time.Hour
)

// EntryRepository defines persistence operations for crontab entries.
type EntryRepository interface {
	Create(ctx context.Context, entry *models.CrontabEntry) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error)
	Update(ctx context.Context, entry *models.CrontabEntry) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastRun(ctx context.Context, id uuid.UUID, status, output string, runAt time.Time) error
	UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error)
}

// ExecutionRepository defines persistence for crontab execution history.
type ExecutionRepository interface {
	Create(ctx context.Context, exec *models.CrontabExecution) error
	ListByEntry(ctx context.Context, entryID uuid.UUID, limit, offset int) ([]*models.CrontabExecution, error)
	CountByEntry(ctx context.Context, entryID uuid.UUID) (int, error)
	DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error)
}

// ExecutionListener is invoked synchronously after an execution row has
// been persisted. The API WebSocket tail handler implements it to push
// completed executions to live subscribers. Listeners must not block —
// they are called from the executor goroutine.
type ExecutionListener interface {
	OnExecution(execution *models.CrontabExecution, entryName string)
}

// Service manages cron job entries and their scheduled execution.
type Service struct {
	entries    EntryRepository
	executions ExecutionRepository
	logger     *logger.Logger

	hostID uuid.UUID

	scheduler *cron.Cron
	cronMu    sync.Mutex
	cronIDs   map[uuid.UUID]cron.EntryID

	listenersMu sync.RWMutex
	listeners   map[*ExecutionListener]struct{}

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewService creates a new crontab service. The logger may be nil — a
// no-op logger is substituted so the constructor signature is uniform
// across modules.
func NewService(entries EntryRepository, executions ExecutionRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		entries:    entries,
		executions: executions,
		logger:     log.Named("crontab"),
		cronIDs:    make(map[uuid.UUID]cron.EntryID),
		listeners:  make(map[*ExecutionListener]struct{}),
		stopCh:     make(chan struct{}),
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start initializes the cron scheduler, loads enabled entries from the
// database, and starts the daily cleanup worker. Safe to call once.
func (s *Service) Start(ctx context.Context, hostID uuid.UUID) error {
	s.hostID = hostID

	s.scheduler = cron.New(cron.WithParser(cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))

	entries, err := s.entries.List(ctx, hostID)
	if err != nil {
		return fmt.Errorf("crontab: load entries: %w", err)
	}

	registered := 0
	for _, e := range entries {
		if !e.Enabled {
			continue
		}
		if err := s.registerEntry(e); err != nil {
			s.logger.Warn("failed to register crontab entry",
				"id", e.ID, "name", e.Name, "schedule", e.Schedule, "error", err)
			continue
		}
		registered++
	}

	s.scheduler.Start()
	s.updateAllNextRun(ctx)

	s.logger.Info("crontab service started",
		"host_id", hostID,
		"entries_loaded", len(entries),
		"entries_registered", registered,
	)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupWorker(ctx)
	}()

	return nil
}

// Stop stops the cron scheduler and waits for in-flight executions.
func (s *Service) Stop() error {
	close(s.stopCh)
	if s.scheduler != nil {
		ctx := s.scheduler.Stop()
		<-ctx.Done()
	}
	s.wg.Wait()
	s.logger.Info("crontab service stopped")
	return nil
}

// HostID returns the default host UUID this service executes against.
func (s *Service) HostID() uuid.UUID { return s.hostID }

// ============================================================================
// Execution listeners (WebSocket tail)
// ============================================================================

// AddExecutionListener registers a listener invoked synchronously after
// each persisted execution. The returned function deregisters the listener.
func (s *Service) AddExecutionListener(l ExecutionListener) func() {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	key := &l
	s.listeners[key] = struct{}{}
	return func() {
		s.listenersMu.Lock()
		defer s.listenersMu.Unlock()
		delete(s.listeners, key)
	}
}

func (s *Service) notify(execution *models.CrontabExecution, entryName string) {
	s.listenersMu.RLock()
	defer s.listenersMu.RUnlock()
	for k := range s.listeners {
		(*k).OnExecution(execution, entryName)
	}
}

// ============================================================================
// CRUD
// ============================================================================

// List returns all crontab entries for a host.
func (s *Service) List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error) {
	return s.entries.List(ctx, hostID)
}

// Get retrieves a crontab entry by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error) {
	return s.entries.GetByID(ctx, id)
}

// Create creates a new crontab entry and registers it in the scheduler
// when Enabled. Validation runs before any DB write.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input models.CreateCrontabInput, userID *uuid.UUID) (*models.CrontabEntry, error) {
	if err := validateCreateInput(input); err != nil {
		return nil, err
	}
	if _, err := cron.ParseStandard(input.Schedule); err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidSchedule, input.Schedule, err)
	}

	cmdType := input.CommandType
	if cmdType == "" {
		cmdType = models.CrontabCommandShell
	}

	entry := &models.CrontabEntry{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        strings.TrimSpace(input.Name),
		Description: input.Description,
		Schedule:    input.Schedule,
		CommandType: cmdType,
		Command:     input.Command,
		ContainerID: input.ContainerID,
		WorkingDir:  input.WorkingDir,
		HTTPMethod:  input.HTTPMethod,
		HTTPURL:     input.HTTPURL,
		Enabled:     input.Enabled,
		CreatedBy:   userID,
	}

	if err := s.entries.Create(ctx, entry); err != nil {
		return nil, err
	}

	if entry.Enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to register new entry", "id", entry.ID, "error", err)
		} else {
			s.updateNextRunForEntry(ctx, entry.ID)
		}
	}

	s.logger.Info("crontab entry created", "id", entry.ID, "name", entry.Name, "schedule", entry.Schedule)
	return entry, nil
}

// Update modifies a crontab entry and re-registers it in the scheduler.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input models.UpdateCrontabInput) (*models.CrontabEntry, error) {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		trimmed := strings.TrimSpace(*input.Name)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: name must not be empty", ErrInvalidInput)
		}
		entry.Name = trimmed
	}
	if input.Description != nil {
		entry.Description = *input.Description
	}
	if input.Schedule != nil {
		if _, err := cron.ParseStandard(*input.Schedule); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidSchedule, *input.Schedule, err)
		}
		entry.Schedule = *input.Schedule
	}
	if input.CommandType != nil {
		if !validCommandType(*input.CommandType) {
			return nil, fmt.Errorf("%w: unknown command_type %q", ErrInvalidInput, *input.CommandType)
		}
		entry.CommandType = *input.CommandType
	}
	if input.Command != nil {
		entry.Command = *input.Command
	}
	if input.ContainerID != nil {
		entry.ContainerID = input.ContainerID
	}
	if input.WorkingDir != nil {
		entry.WorkingDir = input.WorkingDir
	}
	if input.HTTPMethod != nil {
		entry.HTTPMethod = input.HTTPMethod
	}
	if input.HTTPURL != nil {
		entry.HTTPURL = input.HTTPURL
	}
	if input.Enabled != nil {
		entry.Enabled = *input.Enabled
	}

	if err := s.entries.Update(ctx, entry); err != nil {
		return nil, err
	}

	s.unregisterEntry(id)
	if entry.Enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to re-register entry", "id", id, "error", err)
		}
	}
	s.updateNextRunForEntry(ctx, entry.ID)

	s.logger.Info("crontab entry updated", "id", id, "name", entry.Name)
	return entry, nil
}

// Delete removes a crontab entry and its scheduler registration.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	s.unregisterEntry(id)
	if err := s.entries.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("crontab entry deleted", "id", id)
	return nil
}

// ToggleEnabled enables or disables a crontab entry.
func (s *Service) ToggleEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return err
	}
	entry.Enabled = enabled
	if err := s.entries.Update(ctx, entry); err != nil {
		return err
	}

	if enabled {
		if err := s.registerEntry(entry); err != nil {
			s.logger.Warn("failed to register entry", "id", id, "error", err)
		}
		s.updateNextRunForEntry(ctx, id)
	} else {
		s.unregisterEntry(id)
		_ = s.entries.UpdateNextRun(ctx, id, nil)
	}
	return nil
}

// RunNow executes a crontab entry immediately in a background goroutine.
// Errors during execution are not returned synchronously — they land in
// the execution row.
func (s *Service) RunNow(ctx context.Context, id uuid.UUID) error {
	entry, err := s.entries.GetByID(ctx, id)
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.executeEntry(context.Background(), entry)
	}()
	return nil
}

// ListExecutions returns execution history for an entry. The limit is
// capped to 100 by default; callers asking for more than 100 are clamped.
func (s *Service) ListExecutions(ctx context.Context, entryID uuid.UUID, limit, offset int) ([]*models.CrontabExecution, error) {
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.executions.ListByEntry(ctx, entryID, limit, offset)
}

// CountExecutions returns the total execution count for an entry,
// used by API and UI to drive pagination.
func (s *Service) CountExecutions(ctx context.Context, entryID uuid.UUID) (int, error) {
	return s.executions.CountByEntry(ctx, entryID)
}

// GetStats returns aggregate statistics for entries on a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error) {
	return s.entries.GetStats(ctx, hostID)
}

// ============================================================================
// Internal: cron registration
// ============================================================================

func (s *Service) registerEntry(entry *models.CrontabEntry) error {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	if existingID, ok := s.cronIDs[entry.ID]; ok {
		s.scheduler.Remove(existingID)
		delete(s.cronIDs, entry.ID)
	}

	entryID := entry.ID
	cronID, err := s.scheduler.AddFunc(entry.Schedule, func() {
		e, err := s.entries.GetByID(context.Background(), entryID)
		if err != nil {
			s.logger.Error("failed to fetch entry for execution", "id", entryID, "error", err)
			return
		}
		s.executeEntry(context.Background(), e)
	})
	if err != nil {
		return fmt.Errorf("crontab: add schedule %q: %w", entry.Schedule, err)
	}

	s.cronIDs[entry.ID] = cronID
	return nil
}

func (s *Service) unregisterEntry(entryID uuid.UUID) {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	if cronID, ok := s.cronIDs[entryID]; ok {
		s.scheduler.Remove(cronID)
		delete(s.cronIDs, entryID)
	}
}

// ============================================================================
// Internal: command execution
// ============================================================================

func (s *Service) executeEntry(ctx context.Context, entry *models.CrontabEntry) {
	startedAt := time.Now()

	s.logger.Debug("executing crontab entry",
		"id", entry.ID, "name", entry.Name, "type", entry.CommandType)

	output, exitCode, execErr := s.dispatch(ctx, entry)

	finishedAt := time.Now()
	durationMs := finishedAt.Sub(startedAt).Milliseconds()

	status := "success"
	errMsg := ""
	if execErr != nil {
		status = "failed"
		errMsg = execErr.Error()
	}

	if len(output) > MaxOutputBytes {
		output = output[:MaxOutputBytes] + "\n...(truncated)"
	}

	execution := &models.CrontabExecution{
		ID:         uuid.New(),
		EntryID:    entry.ID,
		HostID:     entry.HostID,
		Status:     status,
		Output:     output,
		Error:      errMsg,
		ExitCode:   &exitCode,
		DurationMs: durationMs,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
	}

	if err := s.executions.Create(ctx, execution); err != nil {
		s.logger.Error("failed to record crontab execution", "id", entry.ID, "error", err)
	}

	if err := s.entries.UpdateLastRun(ctx, entry.ID, status, output, startedAt); err != nil {
		s.logger.Error("failed to update crontab last run", "id", entry.ID, "error", err)
	}

	s.updateNextRunForEntry(ctx, entry.ID)
	s.notify(execution, entry.Name)

	s.logger.Info("crontab entry executed",
		"id", entry.ID, "name", entry.Name,
		"status", status, "duration_ms", durationMs,
	)
}

func (s *Service) dispatch(ctx context.Context, entry *models.CrontabEntry) (string, int, error) {
	switch entry.CommandType {
	case models.CrontabCommandShell:
		workingDir := ""
		if entry.WorkingDir != nil {
			workingDir = *entry.WorkingDir
		}
		return s.executeShell(ctx, entry.Command, workingDir)
	case models.CrontabCommandDocker:
		containerID := ""
		if entry.ContainerID != nil {
			containerID = *entry.ContainerID
		}
		return s.executeDocker(ctx, containerID, entry.Command)
	case models.CrontabCommandHTTP:
		method := "GET"
		if entry.HTTPMethod != nil && *entry.HTTPMethod != "" {
			method = strings.ToUpper(*entry.HTTPMethod)
		}
		url := entry.Command
		if entry.HTTPURL != nil && *entry.HTTPURL != "" {
			url = *entry.HTTPURL
		}
		return s.executeHTTP(ctx, method, url)
	default:
		return "", 1, fmt.Errorf("crontab: unknown command_type %q", entry.CommandType)
	}
}

// executeShell runs the command via `sh -c` with an explicit argv slice.
// Using a shell here is intentional — the "shell" command type's purpose
// is to let users write shell pipelines (`grep | wc`, etc.). The argv is
// always [sh, -c, command]; the user-supplied bytes never become argv
// elements other than the script body.
func (s *Service) executeShell(ctx context.Context, command, workingDir string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) // #nosec G204 -- intentional shell invocation for the "shell" command type, see package docstring
	if workingDir != "" {
		cmd.Dir = workingDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n--- STDERR ---\n" + stderr.String()
	}

	if err != nil {
		var exitErr *exec.ExitError
		if stderrors.As(err, &exitErr) {
			return output, exitErr.ExitCode(), err
		}
		return output, 1, err
	}
	return output, 0, nil
}

// executeDocker runs `docker exec` against a container with an explicit
// argv slice. The user-supplied command is passed as a single argument
// to /bin/sh inside the container so multi-token commands and pipelines
// work; the master never builds a shell string itself.
func (s *Service) executeDocker(ctx context.Context, containerID, command string) (string, int, error) {
	if containerID == "" {
		return "", 1, fmt.Errorf("crontab: docker command_type requires container_id")
	}
	if command == "" {
		return "", 1, fmt.Errorf("crontab: docker command_type requires a command")
	}

	args := []string{"exec", containerID, "/bin/sh", "-c", command}
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- explicit argv, never a shell string

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n--- STDERR ---\n" + stderr.String()
	}

	if err != nil {
		var exitErr *exec.ExitError
		if stderrors.As(err, &exitErr) {
			return output, exitErr.ExitCode(), err
		}
		return output, 1, err
	}
	return output, 0, nil
}

// executeHTTP performs the configured HTTP request. Bodies larger than
// HTTPMaxBodyBytes are truncated with a trailing marker so the captured
// output remains bounded.
func (s *Service) executeHTTP(ctx context.Context, method, url string) (string, int, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	reqCtx, cancel := context.WithTimeout(ctx, HTTPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, url, nil)
	if err != nil {
		return "", 1, fmt.Errorf("crontab: create request: %w", err)
	}
	req.Header.Set("User-Agent", "usulnet-crontab/1.0")

	client := &http.Client{Timeout: HTTPRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", 1, fmt.Errorf("crontab: http request failed: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, HTTPMaxBodyBytes+1))
	truncated := false
	if len(body) > HTTPMaxBodyBytes {
		body = body[:HTTPMaxBodyBytes]
		truncated = true
	}

	bodyStr := string(body)
	if truncated {
		bodyStr += "\n...(truncated)"
	}
	if readErr != nil {
		bodyStr += "\n--- READ ERROR ---\n" + readErr.Error()
	}

	output := fmt.Sprintf("HTTP %d %s\n%s", resp.StatusCode, resp.Status, bodyStr)

	if resp.StatusCode >= 400 {
		return output, resp.StatusCode, fmt.Errorf("crontab: http %d: %s", resp.StatusCode, resp.Status)
	}
	return output, 0, nil
}

// ============================================================================
// Internal: helpers
// ============================================================================

func (s *Service) updateAllNextRun(ctx context.Context) {
	s.cronMu.Lock()
	defer s.cronMu.Unlock()

	for entryUUID, cronID := range s.cronIDs {
		cronEntry := s.scheduler.Entry(cronID)
		if !cronEntry.Next.IsZero() {
			next := cronEntry.Next
			_ = s.entries.UpdateNextRun(ctx, entryUUID, &next)
		}
	}
}

func (s *Service) updateNextRunForEntry(ctx context.Context, entryID uuid.UUID) {
	s.cronMu.Lock()
	cronID, ok := s.cronIDs[entryID]
	s.cronMu.Unlock()

	if !ok {
		_ = s.entries.UpdateNextRun(ctx, entryID, nil)
		return
	}

	cronEntry := s.scheduler.Entry(cronID)
	if !cronEntry.Next.IsZero() {
		next := cronEntry.Next
		_ = s.entries.UpdateNextRun(ctx, entryID, &next)
	}
}

func (s *Service) cleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	retention := time.Duration(DefaultExecutionRetentionDays) * 24 * time.Hour
	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.executions.DeleteOlderThan(ctx, retention)
			if err != nil {
				s.logger.Warn("failed to cleanup old executions", "error", err)
			} else if deleted > 0 {
				s.logger.Info("cleaned up old crontab executions", "deleted", deleted)
			}
		}
	}
}

// ============================================================================
// Validation helpers
// ============================================================================

// MaxExecutionsPerPage caps the page size for ListExecutions. Callers can
// request lower values; higher values are clamped to this ceiling.
const MaxExecutionsPerPage = 100

func clampLimit(limit int) int {
	if limit <= 0 {
		return MaxExecutionsPerPage
	}
	if limit > MaxExecutionsPerPage {
		return MaxExecutionsPerPage
	}
	return limit
}

func validCommandType(t models.CrontabCommandType) bool {
	switch t {
	case models.CrontabCommandShell, models.CrontabCommandDocker, models.CrontabCommandHTTP:
		return true
	}
	return false
}

func validateCreateInput(in models.CreateCrontabInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalidInput)
	}
	if strings.TrimSpace(in.Schedule) == "" {
		return fmt.Errorf("%w: schedule must not be empty", ErrInvalidInput)
	}
	cmdType := in.CommandType
	if cmdType == "" {
		cmdType = models.CrontabCommandShell
	}
	if !validCommandType(cmdType) {
		return fmt.Errorf("%w: unknown command_type %q", ErrInvalidInput, in.CommandType)
	}
	switch cmdType {
	case models.CrontabCommandShell:
		if strings.TrimSpace(in.Command) == "" {
			return fmt.Errorf("%w: shell command must not be empty", ErrInvalidInput)
		}
	case models.CrontabCommandDocker:
		if in.ContainerID == nil || strings.TrimSpace(*in.ContainerID) == "" {
			return fmt.Errorf("%w: docker command_type requires container_id", ErrInvalidInput)
		}
		if strings.TrimSpace(in.Command) == "" {
			return fmt.Errorf("%w: docker command_type requires a command", ErrInvalidInput)
		}
	case models.CrontabCommandHTTP:
		url := in.Command
		if in.HTTPURL != nil && *in.HTTPURL != "" {
			url = *in.HTTPURL
		}
		if strings.TrimSpace(url) == "" {
			return fmt.Errorf("%w: http command_type requires a URL", ErrInvalidInput)
		}
	}
	return nil
}
