// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

func TestReconSeverityClass(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"critical", "critical", "text-red-400"},
		{"high", "high", "text-orange-400"},
		{"medium", "medium", "text-yellow-400"},
		{"low", "low", "text-blue-400"},
		{"info", "info", "text-gray-400"},
		{"unknown falls back to gray", "wat", "text-gray-400"},
		{"mixed case", "CRITICAL", "text-red-400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReconSeverityClass(tc.in)
			if !strings.Contains(got, tc.want) {
				t.Errorf("ReconSeverityClass(%q) = %q, want substring %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestReconTargetToView(t *testing.T) {
	hash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tg := &recon.Target{
		ID:        uid,
		Type:      recon.TargetEmail,
		Value:     "alice@example.com",
		Label:     "primary",
		ValueHash: hash,
		CreatedAt: time.Date(2026, 5, 12, 9, 30, 0, 0, time.UTC),
	}

	v := reconTargetToView(tg)

	if v.ID != uid.String() {
		t.Errorf("ID = %q, want %q", v.ID, uid.String())
	}
	if v.Type != "email" {
		t.Errorf("Type = %q, want %q", v.Type, "email")
	}
	if v.Value != "alice@example.com" {
		t.Errorf("Value = %q", v.Value)
	}
	if v.ValueHashPrefix != "deadbeef" {
		t.Errorf("ValueHashPrefix = %q, want %q", v.ValueHashPrefix, "deadbeef")
	}
	if v.CreatedAt != "2026-05-12 09:30" {
		t.Errorf("CreatedAt = %q", v.CreatedAt)
	}
}

func TestReconScanToView_StatusProgress(t *testing.T) {
	target := recon.Target{
		ID:    uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Type:  recon.TargetDomain,
		Value: "example.com",
	}
	idx := map[uuid.UUID]recon.Target{target.ID: target}

	cases := []struct {
		status recon.ScanStatus
		want   int
	}{
		{recon.ScanQueued, 5},
		{recon.ScanRunning, 50},
		{recon.ScanCompleted, 100},
		{recon.ScanFailed, 100},
		{recon.ScanCancelled, 100},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			s := &recon.Scan{
				ID:        uuid.New(),
				TargetID:  target.ID,
				Status:    tc.status,
				Engine:    "spiderfoot",
				CreatedAt: time.Now(),
			}
			v := reconScanToView(s, idx)
			if v.Progress != tc.want {
				t.Errorf("progress for %q = %d, want %d", tc.status, v.Progress, tc.want)
			}
			if v.TargetValue != "example.com" {
				t.Errorf("TargetValue = %q", v.TargetValue)
			}
		})
	}
}

func TestReconScanToView_Duration(t *testing.T) {
	target := recon.Target{ID: uuid.New(), Value: "x", Type: recon.TargetEmail}
	idx := map[uuid.UUID]recon.Target{target.ID: target}
	start := time.Now().Add(-5 * time.Minute)
	end := start.Add(2*time.Minute + 30*time.Second)
	s := &recon.Scan{
		ID:         uuid.New(),
		TargetID:   target.ID,
		Status:     recon.ScanCompleted,
		StartedAt:  &start,
		FinishedAt: &end,
		CreatedAt:  start,
	}
	v := reconScanToView(s, idx)
	if !strings.Contains(v.Duration, "2m") {
		t.Errorf("Duration = %q, want it to contain 2m", v.Duration)
	}
}

func TestReconFindingToView(t *testing.T) {
	f := &recon.Finding{
		ID:         uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		ScanID:     uuid.New(),
		TargetID:   uuid.New(),
		Module:     "hibp",
		Category:   "breach",
		Severity:   recon.SeverityHigh,
		Value:      "alice@example.com",
		Source:     "hibp.api",
		Confidence: 90,
		FirstSeen:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	v := reconFindingToView(f)
	if v.Module != "hibp" || v.Severity != "high" || v.Confidence != 90 {
		t.Errorf("view = %+v", v)
	}
	if v.FirstSeen != "2026-01-01 00:00" {
		t.Errorf("FirstSeen = %q", v.FirstSeen)
	}
}

func TestReconProfileToView(t *testing.T) {
	p := &recon.Profile{
		ID:          uuid.New(),
		Name:        "email_exposure_lite",
		Description: "Light email exposure",
		Kind:        "builtin",
		TargetTypes: []recon.TargetType{recon.TargetEmail},
		Modules:     []string{"hibp", "holehe"},
	}
	v := reconProfileToView(p)
	if v.Name != "email_exposure_lite" || v.Kind != "builtin" {
		t.Errorf("view = %+v", v)
	}
	if len(v.TargetTypes) != 1 || v.TargetTypes[0] != "email" {
		t.Errorf("TargetTypes = %v", v.TargetTypes)
	}
	if len(v.Modules) != 2 {
		t.Errorf("Modules = %v", v.Modules)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "—"},
		{-time.Second, "—"},
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m 30s"},
		{61 * time.Minute, "1h 1m"},
	}
	for _, tc := range cases {
		if got := humanDuration(tc.in); got != tc.want {
			t.Errorf("humanDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// disabledReconAdapter exercises the IsEnabled / IsAcknowledged fall-back
// paths so the handler nil-safety contract is verified.
func TestReconAdapter_DisabledShortCircuits(t *testing.T) {
	a := &reconAdapter{svc: nil, ack: nil, enabled: false}
	if a.IsEnabled() {
		t.Fatal("disabled adapter should report IsEnabled() == false")
	}
	ok, err := a.IsAcknowledged(context.Background())
	if err != nil || ok {
		t.Fatalf("IsAcknowledged() = (%v, %v), want (false, nil)", ok, err)
	}
	dash, err := a.GetDashboard(context.Background())
	if err != nil {
		t.Fatalf("GetDashboard() returned error %v", err)
	}
	if dash == nil || dash.FindingsBySev == nil {
		t.Fatalf("GetDashboard() must return initialized data, got %+v", dash)
	}
}
