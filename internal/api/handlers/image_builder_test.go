// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"bytes"
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
)

// fakeImageBuilderSvc is a tiny stand-in for *imagebuilder.Service that
// implements only the surface the handler needs.
type fakeImageBuilderSvc struct {
	startErr   error
	startResp  *models.ImageBuildJob
	startInput imagebuildersvc.StartBuildOptions
	getErr     error
	getResp    *models.ImageBuildJob
	listResp   []models.ImageBuildJob
	listTotal  int
	stats      *models.ImageBuildJobStats
	templates  []models.DockerfileTemplate
	createT    *models.DockerfileTemplate
	createErr  error
	deleteErr  error
}

func (f *fakeImageBuilderSvc) StartBuild(_ context.Context, opts imagebuildersvc.StartBuildOptions) (*models.ImageBuildJob, error) {
	f.startInput = opts
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.startResp != nil {
		return f.startResp, nil
	}
	now := time.Now()
	return &models.ImageBuildJob{
		ID: uuid.New(), HostID: opts.HostID, Tags: opts.Tags,
		Status: models.BuildJobStatusSuccess, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (f *fakeImageBuilderSvc) GetBuild(_ context.Context, id uuid.UUID) (*models.ImageBuildJob, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResp != nil {
		return f.getResp, nil
	}
	return &models.ImageBuildJob{ID: id, Status: models.BuildJobStatusSuccess}, nil
}

func (f *fakeImageBuilderSvc) ListBuilds(_ context.Context, _ uuid.UUID, _, _ int) ([]models.ImageBuildJob, int, error) {
	return f.listResp, f.listTotal, nil
}

func (f *fakeImageBuilderSvc) GetStats(_ context.Context, _ uuid.UUID) (*models.ImageBuildJobStats, error) {
	if f.stats != nil {
		return f.stats, nil
	}
	return &models.ImageBuildJobStats{}, nil
}

func (f *fakeImageBuilderSvc) ListTemplates(_ context.Context, _ uuid.UUID) ([]models.DockerfileTemplate, error) {
	return f.templates, nil
}

func (f *fakeImageBuilderSvc) GetTemplate(_ context.Context, id uuid.UUID) (*models.DockerfileTemplate, error) {
	for i := range f.templates {
		if f.templates[i].ID == id {
			return &f.templates[i], nil
		}
	}
	return nil, stderrors.New("not found")
}

func (f *fakeImageBuilderSvc) CreateTemplate(_ context.Context, hostID uuid.UUID, name, description, category, dockerfile string, _ *uuid.UUID) (*models.DockerfileTemplate, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	t := &models.DockerfileTemplate{ID: uuid.New(), HostID: hostID, Name: name, Description: description, Category: category, Dockerfile: dockerfile}
	f.createT = t
	return t, nil
}

func (f *fakeImageBuilderSvc) DeleteTemplate(_ context.Context, _ uuid.UUID) error {
	return f.deleteErr
}

func (f *fakeImageBuilderSvc) LogChannel(id uuid.UUID) string {
	return "imagebuilder:logs:" + id.String()
}

func (f *fakeImageBuilderSvc) MaxContextBytes() int64 {
	return 256 * 1024 * 1024
}

// ============================================================================
// Helpers
// ============================================================================

func newImageBuilderTestHandler(svc ImageBuilderService) *ImageBuilderHandler {
	hostID := uuid.New()
	return NewImageBuilderHandler(svc, nil, func(_ *http.Request) uuid.UUID { return hostID }, logger.Nop())
}

// ============================================================================
// Tests
// ============================================================================

func TestImageBuilder_ServiceUnavailableWhenSvcNil(t *testing.T) {
	h := NewImageBuilderHandler(nil, nil, func(_ *http.Request) uuid.UUID { return uuid.New() }, logger.Nop())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListBuilds(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when svc nil, got %d", w.Code)
	}
}

func TestImageBuilder_ListBuildsReturnsRows(t *testing.T) {
	now := time.Now()
	svc := &fakeImageBuilderSvc{
		listResp: []models.ImageBuildJob{
			{ID: uuid.New(), HostID: uuid.New(), Tags: []string{"img:latest"}, Status: models.BuildJobStatusSuccess, CreatedAt: now, UpdatedAt: now},
		},
		listTotal: 1,
	}
	h := newImageBuilderTestHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/?page=1&page_size=10", nil)
	w := httptest.NewRecorder()
	h.ListBuilds(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("expected total=1 in response, got %s", w.Body.String())
	}
}

func TestImageBuilder_StartBuildAcceptedWithDockerfile(t *testing.T) {
	svc := &fakeImageBuilderSvc{}
	h := newImageBuilderTestHandler(svc)
	body := strings.NewReader(`{"tags":["img:latest"],"dockerfile":"FROM alpine:3.21\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.StartBuild(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", w.Code, w.Body.String())
	}
	if svc.startInput.Dockerfile == "" || len(svc.startInput.Tags) != 1 {
		t.Fatalf("expected service to be invoked with parsed body, got %+v", svc.startInput)
	}
}

func TestImageBuilder_StartBuildMapsContextTooLargeTo413(t *testing.T) {
	svc := &fakeImageBuilderSvc{startErr: imagebuildersvc.ErrContextTooLarge}
	h := newImageBuilderTestHandler(svc)
	body := strings.NewReader(`{"tags":["img:latest"],"dockerfile":"FROM alpine:3.21\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.StartBuild(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestImageBuilder_StartBuildMapsBuilderUnavailableTo503(t *testing.T) {
	svc := &fakeImageBuilderSvc{startErr: imagebuildersvc.ErrBuilderUnavailable}
	h := newImageBuilderTestHandler(svc)
	body := strings.NewReader(`{"tags":["img:latest"],"dockerfile":"FROM alpine:3.21\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.StartBuild(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestImageBuilder_StartBuildRejectsInvalidJSON(t *testing.T) {
	svc := &fakeImageBuilderSvc{}
	h := newImageBuilderTestHandler(svc)
	body := strings.NewReader(`{"tags":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.StartBuild(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing tags, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestImageBuilder_StatsReturnsAggregate(t *testing.T) {
	svc := &fakeImageBuilderSvc{stats: &models.ImageBuildJobStats{TotalBuilds: 3, Successful: 2, Failed: 1, AvgDurationMs: 1234}}
	h := newImageBuilderTestHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"total_builds":3`) {
		t.Fatalf("expected total_builds in response, got %s", w.Body.String())
	}
}

func TestImageBuilder_DeleteBuiltinReturns403(t *testing.T) {
	svc := &fakeImageBuilderSvc{deleteErr: imagebuildersvc.ErrBuiltinDelete}
	h := newImageBuilderTestHandler(svc)
	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", uuid.New().String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.DeleteTemplate(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestImageBuilder_CreateTemplateAcceptsValidBody(t *testing.T) {
	svc := &fakeImageBuilderSvc{}
	h := newImageBuilderTestHandler(svc)
	body := bytes.NewReader([]byte(`{"name":"x","dockerfile":"FROM alpine:3.21\n","category":"custom"}`))
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateTemplate(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if svc.createT == nil || svc.createT.Name != "x" {
		t.Fatalf("expected service to receive name, got %+v", svc.createT)
	}
}
