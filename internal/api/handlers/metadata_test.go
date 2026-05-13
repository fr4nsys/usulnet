// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// ---------------------------------------------------------------------------
// stubMetadataService
// ---------------------------------------------------------------------------

// stubMetadataService implements metadata.Service for handler tests.
// Hooks are nil by default so an unexpected call surfaces as a panic.
type stubMetadataService struct {
	createJob     func(context.Context, metadata.CreateJobInput) (*metadata.Job, error)
	getJob        func(context.Context, uuid.UUID) (*metadata.Job, error)
	listJobs      func(context.Context, metadata.ListJobsFilter) ([]metadata.Job, error)
	listArtifacts func(context.Context, uuid.UUID) ([]metadata.Artifact, error)
	openStripped  func(context.Context, uuid.UUID) (io.ReadCloser, error)
}

func (s *stubMetadataService) CreateJob(ctx context.Context, in metadata.CreateJobInput) (*metadata.Job, error) {
	return s.createJob(ctx, in)
}
func (s *stubMetadataService) GetJob(ctx context.Context, id uuid.UUID) (*metadata.Job, error) {
	return s.getJob(ctx, id)
}
func (s *stubMetadataService) ListJobs(ctx context.Context, f metadata.ListJobsFilter) ([]metadata.Job, error) {
	return s.listJobs(ctx, f)
}
func (s *stubMetadataService) ListArtifacts(ctx context.Context, id uuid.UUID) ([]metadata.Artifact, error) {
	return s.listArtifacts(ctx, id)
}
func (s *stubMetadataService) OpenStripped(ctx context.Context, id uuid.UUID) (io.ReadCloser, error) {
	return s.openStripped(ctx, id)
}

// ---------------------------------------------------------------------------
// metadataTestEnv — minimal router with the metadata + ack handlers
// ---------------------------------------------------------------------------

type metadataTestEnv struct {
	router chi.Router
	svc    *stubMetadataService
	ack    *handlers.MemoryAckStore
}

func newMetadataEnv(t *testing.T, enabled, acknowledged bool, limits handlers.MetadataUploadLimits) *metadataTestEnv {
	t.Helper()

	svc := &stubMetadataService{}
	if limits.MaxFileBytes == 0 {
		limits = handlers.DefaultMetadataUploadLimits()
	}
	metaH := handlers.NewMetadataHandler(svc, limits, logger.Nop())

	ack := handlers.NewMemoryAckStore()
	if acknowledged {
		_ = ack.Acknowledge(context.Background(), nil, "test")
	}
	// Recon handler is needed for the ack endpoint path; tests do not
	// exercise its other endpoints.
	reconH := handlers.NewReconHandler(nil, nil, ack, logger.Nop())

	cfg := api.RouterConfig{
		JWTSecret:          testJWTSecret,
		CORSConfig:         middleware.DefaultCORSConfig(),
		RateLimitPerMinute: 10_000,
		RequestTimeout:     5 * time.Second,
		MetricsEnabled:     false,
		ReconEnabled:       enabled,
		ReconAckChecker:    ack,
	}

	h := &api.Handlers{
		Recon:    reconH,
		Metadata: metaH,
	}

	return &metadataTestEnv{
		router: api.NewRouter(cfg, h),
		svc:    svc,
		ack:    ack,
	}
}

// uploadRequest builds a multipart upload request body containing one
// file. The mode form field is set to the supplied value.
func uploadRequest(t *testing.T, files map[string][]byte, mode, token string) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if mode != "" {
		_ = mw.WriteField("mode", mode)
	}
	for name, content := range files {
		w, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("write content: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/metadata/jobs", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func sampleJob() *metadata.Job {
	return &metadata.Job{
		ID:        uuid.New(),
		Source:    metadata.SourceUpload,
		Mode:      metadata.ModeExtract,
		Status:    metadata.JobQueued,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// ===========================================================================
// CreateJob (multipart)
// ===========================================================================

func TestMetadata_CreateJob(t *testing.T) {
	env := newMetadataEnv(t, true, true, handlers.MetadataUploadLimits{})
	job := sampleJob()
	env.svc.createJob = func(_ context.Context, in metadata.CreateJobInput) (*metadata.Job, error) {
		if in.Source != metadata.SourceUpload {
			t.Errorf("unexpected source: %s", in.Source)
		}
		if len(in.Files) != 1 || in.Files[0].Filename != "a.txt" {
			t.Errorf("unexpected files: %+v", in.Files)
		}
		return job, nil
	}

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		req := uploadRequest(t, map[string][]byte{"a.txt": []byte("hello")}, "extract", tok)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		req := uploadRequest(t, map[string][]byte{"a.txt": []byte("hello")}, "extract", tok)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("validation failure (no files)", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		req := uploadRequest(t, nil, "extract", tok)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("validation failure (bad mode)", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		req := uploadRequest(t, map[string][]byte{"a.txt": []byte("x")}, "rotate-cipher", tok)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		req := uploadRequest(t, map[string][]byte{"a.txt": []byte("x")}, "extract", "")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestMetadata_CreateJob_FileTooLarge(t *testing.T) {
	limits := handlers.MetadataUploadLimits{
		MaxFileBytes:  16,
		MaxTotalBytes: 4096,
	}
	env := newMetadataEnv(t, true, true, limits)

	tok := generateTestToken(t, testUser(), "alice", "operator")
	big := make([]byte, 100)
	req := uploadRequest(t, map[string][]byte{"big.bin": big}, "extract", tok)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d. Body: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w, "artifact_too_large")
}

func TestMetadata_CreateJob_TotalBodyTooLarge(t *testing.T) {
	limits := handlers.MetadataUploadLimits{
		MaxFileBytes:  1024 * 1024,
		MaxTotalBytes: 32, // tiny: forces the multipart envelope to overflow
	}
	env := newMetadataEnv(t, true, true, limits)

	tok := generateTestToken(t, testUser(), "alice", "operator")
	req := uploadRequest(t, map[string][]byte{"a.txt": []byte(strings.Repeat("x", 200))}, "extract", tok)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 (envelope), got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ===========================================================================
// ListJobs / GetJob
// ===========================================================================

func TestMetadata_ListJobs(t *testing.T) {
	env := newMetadataEnv(t, true, true, handlers.MetadataUploadLimits{})
	env.svc.listJobs = func(_ context.Context, _ metadata.ListJobsFilter) ([]metadata.Job, error) {
		return []metadata.Job{*sampleJob()}, nil
	}

	t.Run("viewer happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET", "/api/v1/metadata/jobs", "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/metadata/jobs", "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestMetadata_GetJob(t *testing.T) {
	env := newMetadataEnv(t, true, true, handlers.MetadataUploadLimits{})
	job := sampleJob()
	env.svc.getJob = func(_ context.Context, id uuid.UUID) (*metadata.Job, error) {
		if id != job.ID {
			t.Errorf("unexpected id")
		}
		return job, nil
	}
	env.svc.listArtifacts = func(_ context.Context, _ uuid.UUID) ([]metadata.Artifact, error) {
		return []metadata.Artifact{}, nil
	}

	t.Run("viewer happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET", "/api/v1/metadata/jobs/"+job.ID.String(), "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
	t.Run("invalid id", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET", "/api/v1/metadata/jobs/not-uuid", "", tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/metadata/jobs/"+job.ID.String(), "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// ===========================================================================
// DownloadStripped (binary)
// ===========================================================================

func TestMetadata_DownloadStripped(t *testing.T) {
	env := newMetadataEnv(t, true, true, handlers.MetadataUploadLimits{})

	jobID := uuid.New()
	artifactID := uuid.New()
	cleaned := []byte("clean-bytes")

	env.svc.listArtifacts = func(_ context.Context, id uuid.UUID) ([]metadata.Artifact, error) {
		if id != jobID {
			t.Errorf("unexpected job id")
		}
		return []metadata.Artifact{{
			ID:        artifactID,
			JobID:     jobID,
			Filename:  "doc.pdf",
			SizeBytes: int64(len(cleaned)),
		}}, nil
	}
	env.svc.openStripped = func(_ context.Context, id uuid.UUID) (io.ReadCloser, error) {
		if id != artifactID {
			t.Errorf("unexpected artifact id")
		}
		return io.NopCloser(bytes.NewReader(cleaned)), nil
	}

	t.Run("viewer happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET",
			"/api/v1/metadata/jobs/"+jobID.String()+"/artifacts/"+artifactID.String()+"/stripped",
			"", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("unexpected content-type: %s", ct)
		}
		if got := w.Body.Bytes(); !bytes.Equal(got, cleaned) {
			t.Fatalf("unexpected bytes: %q", got)
		}
	})

	t.Run("artifact mismatch -> 404", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET",
			"/api/v1/metadata/jobs/"+jobID.String()+"/artifacts/"+uuid.NewString()+"/stripped",
			"", tok)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET",
			"/api/v1/metadata/jobs/"+jobID.String()+"/artifacts/"+artifactID.String()+"/stripped",
			"", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}
