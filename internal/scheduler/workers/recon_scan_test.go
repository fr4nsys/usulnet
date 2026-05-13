// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

type stubReconScanService struct {
	called atomic.Int32
	err    error
	lastID uuid.UUID
}

func (s *stubReconScanService) RunScan(_ context.Context, id uuid.UUID) error {
	s.called.Add(1)
	s.lastID = id
	return s.err
}

type stubReconScanNotifier struct {
	mu      sync.Mutex
	count   int
	success bool
	msg     string
	scanID  uuid.UUID
}

func (n *stubReconScanNotifier) NotifyScanCompleted(_ context.Context, scanID uuid.UUID, success bool, message string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.count++
	n.scanID = scanID
	n.success = success
	n.msg = message
}

func newJob(t *testing.T, jobType models.JobType, payload any) *models.Job {
	t.Helper()
	j := &models.Job{
		ID:   uuid.New(),
		Type: jobType,
	}
	if err := j.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	return j
}

func TestReconScanWorker_HappyPath(t *testing.T) {
	svc := &stubReconScanService{}
	notif := &stubReconScanNotifier{}
	w := NewReconScanWorker(svc, notif, nil)

	if w.Type() != models.JobTypeReconScan {
		t.Fatalf("Type: %v", w.Type())
	}
	scanID := uuid.New()
	job := newJob(t, models.JobTypeReconScan, map[string]any{"scan_id": scanID.String()})

	got, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, ok := got.(*ReconScanResult)
	if !ok {
		t.Fatalf("result type: %T", got)
	}
	if !res.Success {
		t.Fatalf("expected success result, got: %+v", res)
	}
	if svc.called.Load() != 1 {
		t.Fatalf("service called %d times", svc.called.Load())
	}
	if svc.lastID != scanID {
		t.Fatalf("scan id mismatch: %v vs %v", svc.lastID, scanID)
	}
	if notif.count != 1 || !notif.success {
		t.Fatalf("notifier: count=%d success=%v", notif.count, notif.success)
	}
	if notif.scanID != scanID {
		t.Fatalf("notifier scan id: %v", notif.scanID)
	}
}

func TestReconScanWorker_ServiceError(t *testing.T) {
	svc := &stubReconScanService{err: errors.New("engine boom")}
	notif := &stubReconScanNotifier{}
	w := NewReconScanWorker(svc, notif, nil)

	scanID := uuid.New()
	job := newJob(t, models.JobTypeReconScan, map[string]any{"scan_id": scanID.String()})

	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatalf("expected error")
	}
	if notif.count != 1 || notif.success {
		t.Fatalf("notifier success on failure: %+v", notif)
	}
}

func TestReconScanWorker_InvalidPayload(t *testing.T) {
	svc := &stubReconScanService{}
	w := NewReconScanWorker(svc, nil, nil)
	// Empty payload → uuid.Nil → validation error.
	job := &models.Job{ID: uuid.New(), Type: models.JobTypeReconScan}
	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if svc.called.Load() != 0 {
		t.Fatalf("service should not be called: %d", svc.called.Load())
	}
}

func TestReconScanWorker_NoServiceWired(t *testing.T) {
	w := NewReconScanWorker(nil, nil, nil)
	job := newJob(t, models.JobTypeReconScan, map[string]any{"scan_id": uuid.New().String()})
	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatalf("expected error when service is nil")
	}
}

// ----- Metadata worker -----------------------------------------------------

type stubMetadataJobService struct {
	called atomic.Int32
	err    error
	lastID uuid.UUID
}

func (s *stubMetadataJobService) RunJob(_ context.Context, id uuid.UUID) error {
	s.called.Add(1)
	s.lastID = id
	return s.err
}

type stubMetadataJobNotifier struct {
	count   int
	success bool
}

func (n *stubMetadataJobNotifier) NotifyMetadataJobCompleted(_ context.Context, _ uuid.UUID, success bool, _ string) {
	n.count++
	n.success = success
}

func TestMetadataJobWorker_HappyPath(t *testing.T) {
	svc := &stubMetadataJobService{}
	notif := &stubMetadataJobNotifier{}
	w := NewMetadataJobWorker(svc, notif, nil)

	jobID := uuid.New()
	job := newJob(t, models.JobTypeMetadataJob, map[string]any{"job_id": jobID.String()})

	got, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, ok := got.(*MetadataJobResult)
	if !ok || !res.Success {
		t.Fatalf("result: %+v ok=%v", res, ok)
	}
	if svc.called.Load() != 1 {
		t.Fatalf("service called %d times", svc.called.Load())
	}
	if notif.count != 1 || !notif.success {
		t.Fatalf("notifier: %+v", notif)
	}
}
