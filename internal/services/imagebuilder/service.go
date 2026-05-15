// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package imagebuilder ports the v26.2.7 image builder module forward
// into the v26.5.1 AGPL build. It tracks Dockerfile build jobs against
// the local Docker daemon, persists a small library of starter
// templates, and (when configured) hooks each successful build into the
// existing imagesign service so the resulting image gets a Sigstore
// cosign signature on the way out.
//
// Improvements vs v26.2.7:
//
//   - Build logs stream through Redis pub/sub instead of being buffered
//     in memory inside the service. The handler subscribes per-build and
//     bridges the stream into a WebSocket / SSE response. The output
//     column on the row is filled only at the end with a tail-window of
//     the log so the table view stays bounded.
//   - The build daemon is invoked through the docker.ClientAPI surface
//     the rest of the codebase already depends on; no new socket mount
//     is opened.
//   - Build context uploads are capped at 256 MiB by default
//     (configurable). The cap is enforced at the service boundary so
//     an oversized payload is rejected before it reaches the daemon.
//   - The starter template seeder writes a curated set of AGPL-safe
//     Dockerfile snippets on first start. Each template is tagged
//     IsBuiltin so the UI can hide the delete button.
//   - The optional imagesign hook signs the resulting image when
//     cfg.Sign.Enabled is true; failures are logged but do not flip the
//     build to failed (the image is already on disk by then).
//   - No biz gating, no edition checks, no call-home.
package imagebuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DefaultMaxContextBytes caps the build-context upload at 256 MiB. The
// figure matches the value documented in session-08-image-builder.md
// (Risks section). Operators raise the cap via Config.MaxContextBytes
// when their Dockerfiles ship genuinely large assets.
const DefaultMaxContextBytes int64 = 256 * 1024 * 1024

// DefaultLogTailBytes is the size of the trailing slice of the build log
// persisted to image_build_jobs.output. The Redis pub/sub stream carries
// the full log during the run; the database column only retains the
// tail so a single bad build cannot bloat the row.
const DefaultLogTailBytes = 64 * 1024

// Sentinel errors. API and web handlers map these to typed responses.
var (
	// ErrInvalidInput is returned when the caller supplies malformed
	// fields (empty Dockerfile, no tag, etc.).
	ErrInvalidInput = stderrors.New("imagebuilder: invalid input")

	// ErrContextTooLarge is returned when the build-context upload
	// exceeds Config.MaxContextBytes.
	ErrContextTooLarge = stderrors.New("imagebuilder: build context exceeds maximum size")

	// ErrBuilderUnavailable is returned when the docker client is not
	// configured (typically because the socket is not mounted).
	ErrBuilderUnavailable = stderrors.New("imagebuilder: docker client not configured")

	// ErrBuiltinDelete is returned when a caller tries to delete a
	// built-in template.
	ErrBuiltinDelete = stderrors.New("imagebuilder: built-in templates cannot be deleted")
)

// BuildJobRepository defines persistence for image build jobs.
type BuildJobRepository interface {
	Create(ctx context.Context, job *models.ImageBuildJob) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error)
	Update(ctx context.Context, job *models.ImageBuildJob) error
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error)
}

// TemplateRepository defines persistence for Dockerfile templates.
type TemplateRepository interface {
	Create(ctx context.Context, t *models.DockerfileTemplate) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error)
	Update(ctx context.Context, t *models.DockerfileTemplate) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// DockerBuilder is the narrow surface the service consumes from the
// docker package. Declaring it here lets the unit tests pass a fake.
type DockerBuilder interface {
	ImageBuild(ctx context.Context, buildContext io.Reader, opts types.ImageBuildOptions) (types.ImageBuildResponse, error)
}

// LogPublisher abstracts Redis pub/sub. Production wires in a thin
// adapter over *redis.PubSub; unit tests pass a memory channel so they
// can assert what gets published.
type LogPublisher interface {
	Publish(ctx context.Context, channel string, payload []byte) error
}

// SignHook is the optional integration with the imagesign service. When
// non-nil and the build succeeds, the service calls Sign with the
// resulting image reference. The returned signature reference (SHA256
// of the cosign payload, or empty if signing was disabled) is recorded
// on the job row.
type SignHook func(ctx context.Context, imageRef string) (signatureRef string, err error)

// Config holds runtime knobs for the image builder.
type Config struct {
	// MaxContextBytes caps the build-context tar upload. Defaults to
	// DefaultMaxContextBytes (256 MiB).
	MaxContextBytes int64

	// LogTailBytes is the number of trailing bytes of the build log
	// persisted to the row. Defaults to DefaultLogTailBytes (64 KiB).
	LogTailBytes int

	// LogChannelPrefix is the Redis pub/sub channel prefix. Builds are
	// published to "<prefix>:<build_id>". Empty disables publishing.
	LogChannelPrefix string
}

// DefaultConfig returns the canonical knobs.
func DefaultConfig() Config {
	return Config{
		MaxContextBytes:  DefaultMaxContextBytes,
		LogTailBytes:     DefaultLogTailBytes,
		LogChannelPrefix: "imagebuilder:logs",
	}
}

// Service implements the image builder business logic.
type Service struct {
	builds    BuildJobRepository
	templates TemplateRepository
	docker    DockerBuilder
	publisher LogPublisher
	signHook  SignHook
	cfg       Config
	logger    *logger.Logger
}

// NewService creates a new image builder service. docker, publisher and
// signHook are optional — the service degrades gracefully when any of
// them is nil. A nil logger is replaced with a no-op.
func NewService(builds BuildJobRepository, templates TemplateRepository, docker DockerBuilder, publisher LogPublisher, cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	if cfg.MaxContextBytes <= 0 {
		cfg.MaxContextBytes = DefaultMaxContextBytes
	}
	if cfg.LogTailBytes <= 0 {
		cfg.LogTailBytes = DefaultLogTailBytes
	}
	return &Service{
		builds:    builds,
		templates: templates,
		docker:    docker,
		publisher: publisher,
		cfg:       cfg,
		logger:    log.Named("imagebuilder"),
	}
}

// SetSignHook installs (or replaces) the optional image signing hook.
// Pass nil to disable signing.
func (s *Service) SetSignHook(hook SignHook) {
	s.signHook = hook
}

// LogChannel returns the Redis pub/sub channel for a given build. The
// API handler uses the same helper so the publisher and subscriber stay
// in lock-step.
func (s *Service) LogChannel(buildID uuid.UUID) string {
	prefix := s.cfg.LogChannelPrefix
	if prefix == "" {
		prefix = "imagebuilder:logs"
	}
	return prefix + ":" + buildID.String()
}

// MaxContextBytes returns the configured upload cap. Exported so the
// API handler can produce a precise 413 error.
func (s *Service) MaxContextBytes() int64 {
	return s.cfg.MaxContextBytes
}

// ============================================================================
// Build Jobs
// ============================================================================

// StartBuildOptions bundles the per-build parameters. Promoted to a
// struct so the API handler does not have to track an ever-lengthening
// positional argument list.
type StartBuildOptions struct {
	HostID       uuid.UUID
	Name         string
	Tags         []string
	Dockerfile   string
	ContextPath  string
	BuildContext []byte // raw tar.gz of the build context. May be nil for the inline-Dockerfile case.
	BuildArgs    map[string]string
	Labels       map[string]string
	NoCache      bool
	Pull         bool
	Platform     string
	Target       string
	UserID       *uuid.UUID
}

// StartBuild creates a new build job, queues the build, and returns the
// job row. The actual docker build runs synchronously inside StartBuild
// so callers that want to stream logs subscribe to LogChannel(job.ID)
// before the call returns. The handler handles the dispatch.
//
// Improvements vs v26.2.7: explicit context-size enforcement, real
// Docker invocation (the v26.2.7 service stubbed it out with a fake
// "build completed" string), Redis log streaming with a bounded tail
// persisted, and the optional imagesign hook on success.
func (s *Service) StartBuild(ctx context.Context, opts StartBuildOptions) (*models.ImageBuildJob, error) {
	if strings.TrimSpace(opts.Dockerfile) == "" {
		return nil, fmt.Errorf("%w: dockerfile is required", ErrInvalidInput)
	}
	if len(opts.Tags) == 0 {
		return nil, fmt.Errorf("%w: at least one tag is required", ErrInvalidInput)
	}
	if int64(len(opts.BuildContext)) > s.cfg.MaxContextBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrContextTooLarge, len(opts.BuildContext), s.cfg.MaxContextBytes)
	}

	argsJSON, err := json.Marshal(orEmptyStringMap(opts.BuildArgs))
	if err != nil {
		return nil, fmt.Errorf("marshal build_args: %w", err)
	}
	labelsJSON, err := json.Marshal(orEmptyStringMap(opts.Labels))
	if err != nil {
		return nil, fmt.Errorf("marshal labels: %w", err)
	}

	now := time.Now()
	job := &models.ImageBuildJob{
		ID:          uuid.New(),
		HostID:      opts.HostID,
		Name:        opts.Name,
		Tags:        opts.Tags,
		Dockerfile:  opts.Dockerfile,
		ContextPath: opts.ContextPath,
		BuildArgs:   argsJSON,
		Labels:      labelsJSON,
		Target:      opts.Target,
		NoCache:     opts.NoCache,
		Pull:        opts.Pull,
		Platform:    opts.Platform,
		Status:      models.BuildJobStatusPending,
		CreatedBy:   opts.UserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.builds.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("create build job: %w", err)
	}

	job.Status = models.BuildJobStatusBuilding
	job.StartedAt = &now
	if err := s.builds.Update(ctx, job); err != nil {
		return nil, fmt.Errorf("update build job to building: %w", err)
	}

	s.logger.Info("image build started",
		"build_id", job.ID,
		"host_id", opts.HostID,
		"tags", opts.Tags,
		"name", opts.Name,
		"context_bytes", len(opts.BuildContext),
	)

	tailBuf := newRingBuffer(s.cfg.LogTailBytes)
	buildErr := s.performBuild(ctx, job, opts, tailBuf)

	completed := time.Now()
	job.CompletedAt = &completed
	job.DurationMs = int(completed.Sub(now).Milliseconds())
	job.Output = tailBuf.String()

	if buildErr != nil {
		job.Status = models.BuildJobStatusFailed
		job.ErrorMessage = buildErr.Error()
		s.logger.Error("image build failed",
			"build_id", job.ID,
			"error", buildErr,
		)
	} else {
		job.Status = models.BuildJobStatusSuccess
		s.logger.Info("image build succeeded",
			"build_id", job.ID,
			"duration_ms", job.DurationMs,
			"image_id", job.ImageID,
		)

		if s.signHook != nil && len(opts.Tags) > 0 {
			signRef, signErr := s.signHook(ctx, opts.Tags[0])
			if signErr != nil {
				s.logger.Warn("image build signing failed",
					"build_id", job.ID,
					"image", opts.Tags[0],
					"error", signErr,
				)
			} else {
				job.Signed = true
				job.SignatureRef = signRef
				s.logger.Info("image build signed",
					"build_id", job.ID,
					"signature_ref", signRef,
				)
			}
		}
	}

	s.publishStatus(ctx, job)

	if err := s.builds.Update(ctx, job); err != nil {
		return nil, fmt.Errorf("update build result: %w", err)
	}

	return job, nil
}

// performBuild executes the docker build and bridges the daemon's JSON
// stream into the Redis log channel + the trailing buffer.
func (s *Service) performBuild(ctx context.Context, job *models.ImageBuildJob, opts StartBuildOptions, tail *ringBuffer) error {
	if s.docker == nil {
		return ErrBuilderUnavailable
	}

	contextReader, err := s.assembleContext(opts)
	if err != nil {
		return fmt.Errorf("assemble build context: %w", err)
	}

	buildOpts := types.ImageBuildOptions{
		Tags:        opts.Tags,
		Remove:      true,
		ForceRemove: true,
		PullParent:  opts.Pull,
		NoCache:     opts.NoCache,
		Platform:    opts.Platform,
		Target:      opts.Target,
		Dockerfile:  "Dockerfile",
		BuildArgs:   toBuildArgsPtr(opts.BuildArgs),
		Labels:      opts.Labels,
	}

	resp, err := s.docker.ImageBuild(ctx, contextReader, buildOpts)
	if err != nil {
		return fmt.Errorf("docker build: %w", err)
	}
	defer resp.Body.Close()

	imageID, err := s.streamBuildOutput(ctx, job.ID, resp.Body, tail)
	if err != nil {
		return err
	}
	if imageID != "" {
		job.ImageID = imageID
	}
	return nil
}

// assembleContext produces the build context tar stream the daemon
// expects. When opts.BuildContext is non-nil the caller already wrapped
// the files in a tar.gz; otherwise we synthesize a one-file tar that
// contains just the Dockerfile so a paste-only build still works.
func (s *Service) assembleContext(opts StartBuildOptions) (io.Reader, error) {
	if len(opts.BuildContext) > 0 {
		return bytes.NewReader(opts.BuildContext), nil
	}

	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	body := []byte(opts.Dockerfile)
	hdr := &tar.Header{
		Name:    "Dockerfile",
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

// streamBuildOutput parses the daemon's NDJSON response stream, routing
// each "stream" / "error" / "aux" entry into the tail buffer and the
// Redis log channel. Returns the resolved image ID (parsed from the
// "aux" entry the daemon emits at the end) or an error if the stream
// reports a failure.
func (s *Service) streamBuildOutput(ctx context.Context, buildID uuid.UUID, body io.ReadCloser, tail *ringBuffer) (string, error) {
	channel := s.LogChannel(buildID)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var imageID string
	var lastError string

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg dockerStreamMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			s.publishLog(ctx, channel, line)
			tail.Write(line)
			tail.Write([]byte("\n"))
			continue
		}

		switch {
		case msg.Error != "":
			lastError = msg.Error
			s.publishLog(ctx, channel, []byte("error: "+msg.Error+"\n"))
			tail.Write([]byte("error: " + msg.Error + "\n"))
		case msg.Stream != "":
			s.publishLog(ctx, channel, []byte(msg.Stream))
			tail.Write([]byte(msg.Stream))
		case msg.Status != "":
			line := msg.Status + "\n"
			s.publishLog(ctx, channel, []byte(line))
			tail.Write([]byte(line))
		}
		if msg.Aux != nil && msg.Aux.ID != "" {
			imageID = msg.Aux.ID
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read build output: %w", err)
	}
	if lastError != "" {
		return imageID, fmt.Errorf("docker build reported error: %s", lastError)
	}
	return imageID, nil
}

// publishLog forwards a single log chunk to Redis. The error is logged
// at debug level — a missing publisher must not fail the build.
func (s *Service) publishLog(ctx context.Context, channel string, payload []byte) {
	if s.publisher == nil {
		return
	}
	if err := s.publisher.Publish(ctx, channel, payload); err != nil {
		s.logger.Debug("publish build log failed", "channel", channel, "error", err)
	}
}

// publishStatus emits a single terminal envelope on the log channel so
// subscribers can detect a "finished" signal without polling the API.
func (s *Service) publishStatus(ctx context.Context, job *models.ImageBuildJob) {
	if s.publisher == nil {
		return
	}
	envelope, err := json.Marshal(map[string]any{
		"event":         "status",
		"status":        job.Status,
		"image_id":      job.ImageID,
		"signed":        job.Signed,
		"signature_ref": job.SignatureRef,
		"duration_ms":   job.DurationMs,
		"error_message": job.ErrorMessage,
	})
	if err != nil {
		return
	}
	if err := s.publisher.Publish(ctx, s.LogChannel(job.ID), envelope); err != nil {
		s.logger.Debug("publish build status failed", "build_id", job.ID, "error", err)
	}
}

// GetBuild returns a build job by ID.
func (s *Service) GetBuild(ctx context.Context, id uuid.UUID) (*models.ImageBuildJob, error) {
	return s.builds.GetByID(ctx, id)
}

// ListBuilds returns paginated build jobs for a host.
func (s *Service) ListBuilds(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error) {
	return s.builds.ListByHost(ctx, hostID, limit, offset)
}

// GetStats returns aggregate build statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.ImageBuildJobStats, error) {
	return s.builds.GetStats(ctx, hostID)
}

// ============================================================================
// Dockerfile Templates
// ============================================================================

// ListTemplates returns all Dockerfile templates for a host.
func (s *Service) ListTemplates(ctx context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error) {
	return s.templates.List(ctx, hostID)
}

// GetTemplate returns a template by ID.
func (s *Service) GetTemplate(ctx context.Context, id uuid.UUID) (*models.DockerfileTemplate, error) {
	return s.templates.GetByID(ctx, id)
}

// CreateTemplate creates a new user-defined Dockerfile template. Builtin
// templates are seeded via SeedBuiltinTemplates and never created via
// this entry point.
func (s *Service) CreateTemplate(ctx context.Context, hostID uuid.UUID, name, description, category, dockerfile string, userID *uuid.UUID) (*models.DockerfileTemplate, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if strings.TrimSpace(dockerfile) == "" {
		return nil, fmt.Errorf("%w: dockerfile is required", ErrInvalidInput)
	}
	if category == "" {
		category = "custom"
	}
	t := &models.DockerfileTemplate{
		ID:            uuid.New(),
		HostID:        hostID,
		Name:          name,
		Description:   description,
		Category:      category,
		Dockerfile:    dockerfile,
		DefaultArgs:   json.RawMessage("{}"),
		DefaultLabels: json.RawMessage("{}"),
		CreatedBy:     userID,
	}

	if err := s.templates.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("create dockerfile template: %w", err)
	}

	s.logger.Info("created dockerfile template",
		"template_id", t.ID,
		"name", name,
		"category", category,
	)

	return t, nil
}

// DeleteTemplate deletes a Dockerfile template, refusing to delete one
// that the binary seeded.
func (s *Service) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	t, err := s.templates.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if t.IsBuiltin {
		return ErrBuiltinDelete
	}
	return s.templates.Delete(ctx, id)
}

// SeedBuiltinTemplates ensures the curated AGPL-compatible starter
// templates are present for the given host. Calling SeedBuiltinTemplates
// twice is a no-op — the seeder skips templates whose name + IsBuiltin
// pair already exists.
//
// Each shipped template is a minimal Dockerfile snippet that pulls only
// from public, AGPL-compatible upstreams (alpine, debian-slim, the
// official language image families). Operators add proprietary content
// via user-defined templates.
func (s *Service) SeedBuiltinTemplates(ctx context.Context, hostID uuid.UUID) error {
	existing, err := s.templates.List(ctx, hostID)
	if err != nil {
		return fmt.Errorf("list templates: %w", err)
	}
	have := make(map[string]bool, len(existing))
	for _, t := range existing {
		if t.IsBuiltin {
			have[t.Name] = true
		}
	}

	for _, tpl := range builtinTemplates() {
		if have[tpl.Name] {
			continue
		}
		t := &models.DockerfileTemplate{
			ID:            uuid.New(),
			HostID:        hostID,
			Name:          tpl.Name,
			Description:   tpl.Description,
			Category:      tpl.Category,
			Dockerfile:    tpl.Dockerfile,
			DefaultArgs:   json.RawMessage("{}"),
			DefaultLabels: json.RawMessage("{}"),
			IsBuiltin:     true,
		}
		if err := s.templates.Create(ctx, t); err != nil {
			return fmt.Errorf("seed template %q: %w", tpl.Name, err)
		}
		s.logger.Info("seeded builtin dockerfile template",
			"template_id", t.ID,
			"name", tpl.Name,
			"category", tpl.Category,
		)
	}
	return nil
}

// ============================================================================
// Internal helpers
// ============================================================================

// dockerStreamMsg matches the JSON envelope the daemon streams for each
// build step. Only the fields we actually consume are decoded.
type dockerStreamMsg struct {
	Stream string `json:"stream,omitempty"`
	Error  string `json:"error,omitempty"`
	Status string `json:"status,omitempty"`
	Aux    *struct {
		ID string `json:"ID,omitempty"`
	} `json:"aux,omitempty"`
}

// orEmptyStringMap normalises a nil map into an empty one so the JSON
// column always holds a real {} object.
func orEmptyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}

// toBuildArgsPtr converts the string map to the *string map the docker
// SDK expects. A nil map yields a nil result so the SDK omits the field
// entirely.
func toBuildArgsPtr(in map[string]string) map[string]*string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*string, len(in))
	for k, v := range in {
		v := v
		out[k] = &v
	}
	return out
}

// ringBuffer is a fixed-capacity append-only buffer used to hold the
// trailing window of the build log. Writes past the cap drop the oldest
// bytes. Not safe for concurrent use — the build path is single-threaded.
type ringBuffer struct {
	cap  int
	data []byte
}

func newRingBuffer(cap int) *ringBuffer {
	if cap <= 0 {
		cap = DefaultLogTailBytes
	}
	return &ringBuffer{cap: cap, data: make([]byte, 0, cap)}
}

func (r *ringBuffer) Write(b []byte) {
	if len(b) >= r.cap {
		// Truncate to last r.cap bytes.
		r.data = append(r.data[:0], b[len(b)-r.cap:]...)
		return
	}
	if len(r.data)+len(b) <= r.cap {
		r.data = append(r.data, b...)
		return
	}
	overflow := len(r.data) + len(b) - r.cap
	r.data = append(r.data[overflow:], b...)
}

func (r *ringBuffer) String() string {
	return string(r.data)
}
