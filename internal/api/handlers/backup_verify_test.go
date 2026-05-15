// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/models"
	backupverifysvc "github.com/fr4nsys/usulnet/internal/services/backupverify"
)

type stubBackupVerifySvc struct {
	runErr         error
	runResult      *models.BackupVerification
	listErr        error
	listResult     []models.BackupVerification
	listTotal      int
	getResult      *models.BackupVerification
	getErr         error
	stats          *models.BackupVerificationStats
	statsErr       error
	createErr      error
	createResult   *models.BackupVerificationSchedule
	listSchedRes   []models.BackupVerificationSchedule
	listSchedErr   error
	deleteSchedErr error

	// recorded call args
	lastRunBackupID uuid.UUID
	lastRunMethod   models.VerificationMethod
}

func (s *stubBackupVerifySvc) RunVerification(_ context.Context, backupID uuid.UUID, method models.VerificationMethod, _ *uuid.UUID) (*models.BackupVerification, error) {
	s.lastRunBackupID = backupID
	s.lastRunMethod = method
	if s.runErr != nil {
		return nil, s.runErr
	}
	if s.runResult != nil {
		return s.runResult, nil
	}
	return &models.BackupVerification{
		ID:       uuid.New(),
		BackupID: backupID,
		Status:   models.VerificationStatusPassed,
		Method:   method,
	}, nil
}

func (s *stubBackupVerifySvc) ListVerifications(_ context.Context, _ uuid.UUID, _, _ int) ([]models.BackupVerification, int, error) {
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	return s.listResult, s.listTotal, nil
}

func (s *stubBackupVerifySvc) ListByBackup(_ context.Context, _ uuid.UUID) ([]models.BackupVerification, error) {
	return s.listResult, nil
}

func (s *stubBackupVerifySvc) GetVerification(_ context.Context, _ uuid.UUID) (*models.BackupVerification, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.getResult, nil
}

func (s *stubBackupVerifySvc) GetStats(_ context.Context, _ uuid.UUID) (*models.BackupVerificationStats, error) {
	if s.statsErr != nil {
		return nil, s.statsErr
	}
	return s.stats, nil
}

func (s *stubBackupVerifySvc) ListSchedules(_ context.Context, _ uuid.UUID) ([]models.BackupVerificationSchedule, error) {
	if s.listSchedErr != nil {
		return nil, s.listSchedErr
	}
	return s.listSchedRes, nil
}

func (s *stubBackupVerifySvc) GetSchedule(_ context.Context, _ uuid.UUID) (*models.BackupVerificationSchedule, error) {
	return s.createResult, nil
}

func (s *stubBackupVerifySvc) CreateSchedule(_ context.Context, _ uuid.UUID, _, _ string, _ int) (*models.BackupVerificationSchedule, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.createResult != nil {
		return s.createResult, nil
	}
	return &models.BackupVerificationSchedule{
		ID:        uuid.New(),
		HostID:    uuid.New(),
		Schedule:  "0 3 * * 0",
		Method:    "extract",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (s *stubBackupVerifySvc) UpdateSchedule(_ context.Context, _ uuid.UUID, _, _ *string, _ *int, _ *bool) (*models.BackupVerificationSchedule, error) {
	return s.createResult, nil
}

func (s *stubBackupVerifySvc) DeleteSchedule(_ context.Context, _ uuid.UUID) error {
	return s.deleteSchedErr
}

func backupVerifyTestHandler(svc *stubBackupVerifySvc) *handlers.BackupVerifyHandler {
	host := uuid.New()
	return handlers.NewBackupVerifyHandler(svc, func(_ *http.Request) uuid.UUID { return host }, nil)
}

func TestBackupVerifyHandler_RunVerify_DefaultMethod(t *testing.T) {
	svc := &stubBackupVerifySvc{}
	h := backupVerifyTestHandler(svc)

	backupID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/run/"+backupID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("backup_id", backupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.RunVerify(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	if svc.lastRunMethod != models.VerificationMethodExtract {
		t.Fatalf("default method should be extract, got %q", svc.lastRunMethod)
	}
}

func TestBackupVerifyHandler_RunVerify_CustomMethod(t *testing.T) {
	svc := &stubBackupVerifySvc{}
	h := backupVerifyTestHandler(svc)

	backupID := uuid.New()
	body, _ := json.Marshal(map[string]string{"method": "container"})
	req := httptest.NewRequest(http.MethodPost, "/run/"+backupID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("backup_id", backupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.RunVerify(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	if svc.lastRunMethod != models.VerificationMethodContainer {
		t.Fatalf("method = %q, want container", svc.lastRunMethod)
	}
}

func TestBackupVerifyHandler_RunVerify_BadID(t *testing.T) {
	svc := &stubBackupVerifySvc{}
	h := backupVerifyTestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/run/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("backup_id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.RunVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestBackupVerifyHandler_RunVerify_ServiceErrorMaps(t *testing.T) {
	svc := &stubBackupVerifySvc{runErr: backupverifysvc.ErrInvalidMethod}
	h := backupVerifyTestHandler(svc)

	backupID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/run/"+backupID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("backup_id", backupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.RunVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid input mapping)", w.Code)
	}
}

func TestBackupVerifyHandler_ListRuns(t *testing.T) {
	now := time.Now()
	svc := &stubBackupVerifySvc{
		listResult: []models.BackupVerification{
			{ID: uuid.New(), BackupID: uuid.New(), HostID: uuid.New(), Status: models.VerificationStatusPassed, CreatedAt: now},
		},
		listTotal: 1,
	}
	h := backupVerifyTestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/runs", nil)
	w := httptest.NewRecorder()
	h.ListRuns(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var page struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1", page.Total)
	}
}

func TestBackupVerifyHandler_GetStats(t *testing.T) {
	svc := &stubBackupVerifySvc{
		stats: &models.BackupVerificationStats{
			TotalVerified: 5,
			Passed:        4,
			Failed:        1,
			PassRate:      80.0,
		},
	}
	h := backupVerifyTestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	h.GetStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"total_verified":5`) {
		t.Fatalf("response missing total_verified: %s", body)
	}
}

func TestBackupVerifyHandler_NilService(t *testing.T) {
	h := handlers.NewBackupVerifyHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/runs", nil)
	w := httptest.NewRecorder()
	h.ListRuns(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestBackupVerifyHandler_CreateSchedule_ValidatesInput(t *testing.T) {
	svc := &stubBackupVerifySvc{createErr: errors.New("simulated")}
	h := backupVerifyTestHandler(svc)

	hostID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"host_id":     hostID,
		"schedule":    "0 3 * * 0",
		"method":      "extract",
		"max_backups": 5,
	})
	req := httptest.NewRequest(http.MethodPost, "/schedules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	w := httptest.NewRecorder()
	h.CreateSchedule(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for service error", w.Code)
	}
}

func TestBackupVerifyHandler_DeleteSchedule(t *testing.T) {
	svc := &stubBackupVerifySvc{}
	h := backupVerifyTestHandler(svc)

	id := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/schedules/"+id.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.DeleteSchedule(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}
