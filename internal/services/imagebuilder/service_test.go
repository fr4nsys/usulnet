// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package imagebuilder

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Fakes
// ============================================================================

type fakeBuildJobRepo struct {
	mu    sync.Mutex
	rows  map[uuid.UUID]*models.ImageBuildJob
	stats *models.ImageBuildJobStats
}

func newFakeBuildJobRepo() *fakeBuildJobRepo {
	return &fakeBuildJobRepo{rows: map[uuid.UUID]*models.ImageBuildJob{}}
}

func (f *fakeBuildJobRepo) Create(_ context.Context, j *models.ImageBuildJob) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	cp := *j
	f.rows[j.ID] = &cp
	return nil
}

func (f *fakeBuildJobRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ImageBuildJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *row
	return &cp, nil
}

func (f *fakeBuildJobRepo) Update(_ context.Context, j *models.ImageBuildJob) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *j
	f.rows[j.ID] = &cp
	return nil
}

func (f *fakeBuildJobRepo) ListByHost(_ context.Context, hostID uuid.UUID, limit, offset int) ([]models.ImageBuildJob, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.ImageBuildJob, 0, len(f.rows))
	for _, j := range f.rows {
		if j.HostID == hostID {
			out = append(out, *j)
		}
	}
	total := len(out)
	if offset > len(out) {
		return nil, total, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], total, nil
}

func (f *fakeBuildJobRepo) GetStats(_ context.Context, _ uuid.UUID) (*models.ImageBuildJobStats, error) {
	if f.stats != nil {
		return f.stats, nil
	}
	return &models.ImageBuildJobStats{}, nil
}

type fakeTemplateRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.DockerfileTemplate
}

func newFakeTemplateRepo() *fakeTemplateRepo {
	return &fakeTemplateRepo{rows: map[uuid.UUID]*models.DockerfileTemplate{}}
}

func (f *fakeTemplateRepo) Create(_ context.Context, t *models.DockerfileTemplate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	cp := *t
	f.rows[t.ID] = &cp
	return nil
}

func (f *fakeTemplateRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DockerfileTemplate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *row
	return &cp, nil
}

func (f *fakeTemplateRepo) List(_ context.Context, hostID uuid.UUID) ([]models.DockerfileTemplate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.DockerfileTemplate, 0, len(f.rows))
	for _, t := range f.rows {
		if t.HostID == hostID {
			out = append(out, *t)
		}
	}
	return out, nil
}

func (f *fakeTemplateRepo) Update(_ context.Context, t *models.DockerfileTemplate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *t
	f.rows[t.ID] = &cp
	return nil
}

func (f *fakeTemplateRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, id)
	return nil
}

// fakeDocker bridges into Service.performBuild. The body it returns is
// the daemon's NDJSON response stream.
type fakeDocker struct {
	mu       sync.Mutex
	requests []types.ImageBuildOptions
	body     []byte
	err      error
}

func (f *fakeDocker) ImageBuild(_ context.Context, _ io.Reader, opts types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	f.mu.Lock()
	f.requests = append(f.requests, opts)
	f.mu.Unlock()
	if f.err != nil {
		return types.ImageBuildResponse{}, f.err
	}
	return types.ImageBuildResponse{
		Body: io.NopCloser(bytes.NewReader(f.body)),
	}, nil
}

// memoryPublisher is a LogPublisher that records every write so tests can
// assert on the exact stream a build emitted.
type memoryPublisher struct {
	mu      sync.Mutex
	entries map[string][][]byte
}

func newMemoryPublisher() *memoryPublisher {
	return &memoryPublisher{entries: map[string][][]byte{}}
}

func (p *memoryPublisher) Publish(_ context.Context, channel string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	p.entries[channel] = append(p.entries[channel], cp)
	return nil
}

func (p *memoryPublisher) joined(channel string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	for _, e := range p.entries[channel] {
		b.Write(e)
	}
	return b.String()
}

// ============================================================================
// Tests
// ============================================================================

func TestStartBuild_RejectsEmptyDockerfile(t *testing.T) {
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, DefaultConfig(), logger.Nop())
	_, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID: uuid.New(),
		Tags:   []string{"img:latest"},
	})
	if !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestStartBuild_RejectsMissingTags(t *testing.T) {
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, DefaultConfig(), logger.Nop())
	_, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
	})
	if !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestStartBuild_EnforcesContextSizeCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxContextBytes = 1024
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, cfg, logger.Nop())
	_, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:       uuid.New(),
		Dockerfile:   "FROM alpine:3.21\n",
		Tags:         []string{"img:latest"},
		BuildContext: bytes.Repeat([]byte("x"), 2*1024),
	})
	if !stderrors.Is(err, ErrContextTooLarge) {
		t.Fatalf("expected ErrContextTooLarge, got %v", err)
	}
}

func TestStartBuild_FailsWhenDockerNil(t *testing.T) {
	repo := newFakeBuildJobRepo()
	svc := NewService(repo, newFakeTemplateRepo(), nil, nil, DefaultConfig(), logger.Nop())
	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
		Tags:       []string{"img:latest"},
	})
	if err != nil {
		t.Fatalf("StartBuild returned err: %v", err)
	}
	if job.Status != models.BuildJobStatusFailed {
		t.Fatalf("expected status=failed when docker is nil, got %s", job.Status)
	}
	if !strings.Contains(job.ErrorMessage, "docker client not configured") {
		t.Fatalf("expected ErrBuilderUnavailable message in row, got %q", job.ErrorMessage)
	}
}

func TestStartBuild_StreamsLogsViaPublisher_AndCapturesImageID(t *testing.T) {
	body := strings.Join([]string{
		`{"stream":"Step 1/1 : FROM alpine:3.21\n"}`,
		`{"stream":" ---> a1b2c3d4e5f6\n"}`,
		`{"aux":{"ID":"sha256:deadbeefcafe"}}`,
	}, "\n")
	docker := &fakeDocker{body: []byte(body)}
	pub := newMemoryPublisher()
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), docker, pub, DefaultConfig(), logger.Nop())

	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
		Tags:       []string{"img:latest"},
	})
	if err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if job.Status != models.BuildJobStatusSuccess {
		t.Fatalf("expected status=success, got %s (err=%q)", job.Status, job.ErrorMessage)
	}
	if job.ImageID != "sha256:deadbeefcafe" {
		t.Fatalf("expected ImageID parsed from aux, got %q", job.ImageID)
	}
	channel := svc.LogChannel(job.ID)
	streamed := pub.joined(channel)
	if !strings.Contains(streamed, "Step 1/1 : FROM alpine:3.21") {
		t.Fatalf("expected build log to be published, got %q", streamed)
	}
	if !strings.Contains(streamed, "\"event\":\"status\"") {
		t.Fatalf("expected terminal status envelope, got %q", streamed)
	}
}

func TestStartBuild_FlagsErrorWhenDaemonReportsOne(t *testing.T) {
	body := `{"stream":"Step 1/1 : FROM busted:bad\n"}` + "\n" +
		`{"error":"pull access denied"}`
	docker := &fakeDocker{body: []byte(body)}
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), docker, nil, DefaultConfig(), logger.Nop())

	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM busted:bad\n",
		Tags:       []string{"img:latest"},
	})
	if err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if job.Status != models.BuildJobStatusFailed {
		t.Fatalf("expected status=failed, got %s", job.Status)
	}
	if !strings.Contains(job.ErrorMessage, "pull access denied") {
		t.Fatalf("expected daemon error captured, got %q", job.ErrorMessage)
	}
}

func TestStartBuild_FailingDaemonInvocationStillUpdatesRow(t *testing.T) {
	docker := &fakeDocker{err: stderrors.New("connection refused")}
	repo := newFakeBuildJobRepo()
	svc := NewService(repo, newFakeTemplateRepo(), docker, nil, DefaultConfig(), logger.Nop())

	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
		Tags:       []string{"img:latest"},
	})
	if err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if job.Status != models.BuildJobStatusFailed {
		t.Fatalf("expected status=failed, got %s", job.Status)
	}
	if !strings.Contains(job.ErrorMessage, "connection refused") {
		t.Fatalf("expected docker err in message, got %q", job.ErrorMessage)
	}
}

func TestStartBuild_InvokesSignHookOnSuccess(t *testing.T) {
	body := `{"aux":{"ID":"sha256:cafebabefeed"}}`
	docker := &fakeDocker{body: []byte(body)}
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), docker, nil, DefaultConfig(), logger.Nop())

	called := false
	svc.SetSignHook(func(_ context.Context, ref string) (string, error) {
		called = true
		if ref != "img:latest" {
			t.Fatalf("expected first tag to be passed to sign hook, got %q", ref)
		}
		return "sig-123", nil
	})

	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
		Tags:       []string{"img:latest", "img:sha"},
	})
	if err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if !called {
		t.Fatalf("sign hook was not called on success")
	}
	if !job.Signed || job.SignatureRef != "sig-123" {
		t.Fatalf("expected job.Signed=true and SignatureRef=sig-123, got %+v", job)
	}
}

func TestStartBuild_SignHookFailureDoesNotFlipBuildStatus(t *testing.T) {
	body := `{"aux":{"ID":"sha256:cafe"}}`
	docker := &fakeDocker{body: []byte(body)}
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), docker, nil, DefaultConfig(), logger.Nop())

	svc.SetSignHook(func(_ context.Context, _ string) (string, error) {
		return "", stderrors.New("cosign not on path")
	})

	job, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\n",
		Tags:       []string{"img:latest"},
	})
	if err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if job.Status != models.BuildJobStatusSuccess {
		t.Fatalf("expected build to remain success when signing fails, got %s", job.Status)
	}
	if job.Signed {
		t.Fatalf("expected job.Signed=false when sign hook errored")
	}
}

func TestStartBuild_AssemblesContextWhenNoTarbox(t *testing.T) {
	docker := &fakeDocker{body: []byte(`{"aux":{"ID":"sha256:zzz"}}`)}
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), docker, nil, DefaultConfig(), logger.Nop())

	if _, err := svc.StartBuild(context.Background(), StartBuildOptions{
		HostID:     uuid.New(),
		Dockerfile: "FROM alpine:3.21\nCMD echo hello\n",
		Tags:       []string{"img:latest"},
	}); err != nil {
		t.Fatalf("StartBuild err: %v", err)
	}
	if got := len(docker.requests); got != 1 {
		t.Fatalf("expected exactly one ImageBuild call, got %d", got)
	}
	opts := docker.requests[0]
	if opts.Dockerfile != "Dockerfile" {
		t.Fatalf("expected synthesized tar with Dockerfile entry, got %q", opts.Dockerfile)
	}
	if !opts.Remove || !opts.ForceRemove {
		t.Fatalf("expected remove flags set on build opts: %+v", opts)
	}
}

func TestSeedBuiltinTemplates_IsIdempotent(t *testing.T) {
	repo := newFakeTemplateRepo()
	svc := NewService(newFakeBuildJobRepo(), repo, nil, nil, DefaultConfig(), logger.Nop())
	host := uuid.New()
	if err := svc.SeedBuiltinTemplates(context.Background(), host); err != nil {
		t.Fatalf("first seed err: %v", err)
	}
	first := len(repo.rows)
	if first == 0 {
		t.Fatalf("expected at least one builtin template seeded")
	}
	if err := svc.SeedBuiltinTemplates(context.Background(), host); err != nil {
		t.Fatalf("second seed err: %v", err)
	}
	if got := len(repo.rows); got != first {
		t.Fatalf("expected idempotent seed (%d rows), got %d", first, got)
	}
}

func TestDeleteTemplate_RefusesBuiltin(t *testing.T) {
	repo := newFakeTemplateRepo()
	svc := NewService(newFakeBuildJobRepo(), repo, nil, nil, DefaultConfig(), logger.Nop())
	host := uuid.New()
	if err := svc.SeedBuiltinTemplates(context.Background(), host); err != nil {
		t.Fatalf("seed err: %v", err)
	}
	var first uuid.UUID
	for id := range repo.rows {
		first = id
		break
	}
	err := svc.DeleteTemplate(context.Background(), first)
	if !stderrors.Is(err, ErrBuiltinDelete) {
		t.Fatalf("expected ErrBuiltinDelete, got %v", err)
	}
}

func TestCreateTemplate_RejectsEmptyFields(t *testing.T) {
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, DefaultConfig(), logger.Nop())
	if _, err := svc.CreateTemplate(context.Background(), uuid.New(), "", "", "custom", "FROM alpine\n", nil); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty name, got %v", err)
	}
	if _, err := svc.CreateTemplate(context.Background(), uuid.New(), "name", "", "custom", "", nil); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty dockerfile, got %v", err)
	}
}

func TestCreateTemplate_DefaultsCategoryToCustom(t *testing.T) {
	repo := newFakeTemplateRepo()
	svc := NewService(newFakeBuildJobRepo(), repo, nil, nil, DefaultConfig(), logger.Nop())
	t1, err := svc.CreateTemplate(context.Background(), uuid.New(), "n", "d", "", "FROM alpine\n", nil)
	if err != nil {
		t.Fatalf("CreateTemplate err: %v", err)
	}
	if t1.Category != "custom" {
		t.Fatalf("expected default category=custom, got %q", t1.Category)
	}
}

func TestRingBuffer_TrimsToTail(t *testing.T) {
	buf := newRingBuffer(8)
	buf.Write([]byte("abcdefghijkl")) // 12 bytes; ring keeps last 8
	if got := buf.String(); got != "efghijkl" {
		t.Fatalf("expected trimmed tail, got %q", got)
	}
}

func TestRingBuffer_AppendsAndOverflows(t *testing.T) {
	buf := newRingBuffer(8)
	buf.Write([]byte("abcd"))
	buf.Write([]byte("efghi")) // total 9 → drop one byte
	if got := buf.String(); got != "bcdefghi" {
		t.Fatalf("expected sliding overflow, got %q", got)
	}
}

func TestLogChannel_DefaultsPrefix(t *testing.T) {
	cfg := Config{}
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, cfg, logger.Nop())
	id := uuid.New()
	want := "imagebuilder:logs:" + id.String()
	if got := svc.LogChannel(id); got != want {
		t.Fatalf("LogChannel default mismatch: %s", got)
	}
}

func TestLogChannel_HonoursOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogChannelPrefix = "custom"
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, cfg, logger.Nop())
	id := uuid.New()
	want := fmt.Sprintf("custom:%s", id)
	if got := svc.LogChannel(id); got != want {
		t.Fatalf("LogChannel override mismatch: %s", got)
	}
}

func TestListAndStats_ProxyToRepo(t *testing.T) {
	repo := newFakeBuildJobRepo()
	svc := NewService(repo, newFakeTemplateRepo(), nil, nil, DefaultConfig(), logger.Nop())
	host := uuid.New()
	for i := 0; i < 3; i++ {
		_ = repo.Create(context.Background(), &models.ImageBuildJob{HostID: host, Status: models.BuildJobStatusSuccess, Tags: []string{"x"}})
	}
	repo.stats = &models.ImageBuildJobStats{TotalBuilds: 3, Successful: 3}

	rows, total, err := svc.ListBuilds(context.Background(), host, 10, 0)
	if err != nil {
		t.Fatalf("ListBuilds err: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("expected 3 rows, got rows=%d total=%d", len(rows), total)
	}

	stats, err := svc.GetStats(context.Background(), host)
	if err != nil {
		t.Fatalf("GetStats err: %v", err)
	}
	if stats.TotalBuilds != 3 || stats.Successful != 3 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestNewService_NilLoggerAndZeroConfigStillFunctional(t *testing.T) {
	svc := NewService(newFakeBuildJobRepo(), newFakeTemplateRepo(), nil, nil, Config{}, nil)
	if svc.cfg.MaxContextBytes != DefaultMaxContextBytes {
		t.Fatalf("expected zero-config MaxContextBytes to default to %d, got %d", DefaultMaxContextBytes, svc.cfg.MaxContextBytes)
	}
	if svc.cfg.LogTailBytes != DefaultLogTailBytes {
		t.Fatalf("expected zero-config LogTailBytes to default, got %d", svc.cfg.LogTailBytes)
	}
}

func TestRedisLogPublisher_NilSafe(t *testing.T) {
	pub := NewRedisLogPublisher(nil)
	if err := pub.Publish(context.Background(), "ch", []byte("x")); err != nil {
		t.Fatalf("expected nil-safe publish, got %v", err)
	}
	if got := pub.PubSub(); got != nil {
		t.Fatalf("expected nil pub-sub when wrapper is empty, got %v", got)
	}
}
