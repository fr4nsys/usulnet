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

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{42, "42 B"},
		{2048, "2.0 KB"},
		{5 * 1024 * 1024, "5.0 MB"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := humanBytes(tc.in); got != tc.want {
				t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFlattenExtracted(t *testing.T) {
	in := map[string]any{
		"Camera": "Pixel 6",
		"Date":   "2026-01-01",
		"GPS":    map[string]string{"lat": "40.0", "lon": "-3.7"},
	}
	out := flattenExtracted(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 fields, got %d (%v)", len(out), out)
	}
	// Sorted by key.
	wantKeys := []string{"Camera", "Date", "GPS"}
	for i, f := range out {
		if f.Key != wantKeys[i] {
			t.Errorf("field[%d] = %q, want %q", i, f.Key, wantKeys[i])
		}
	}
	// GPS is a nested map; expect JSON-marshaled value.
	gps := out[2].Value
	if !strings.Contains(gps, "\"lat\"") {
		t.Errorf("GPS value should be JSON, got %q", gps)
	}
}

func TestMetadataJobToView(t *testing.T) {
	started := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	finished := started.Add(45 * time.Second)
	j := &metadata.Job{
		ID:            uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		Source:        metadata.SourceUpload,
		Mode:          metadata.ModeBoth,
		Status:        metadata.JobCompleted,
		ArtifactCount: 3,
		StartedAt:     &started,
		FinishedAt:    &finished,
		CreatedAt:     started,
	}
	v := metadataJobToView(j)
	if v.Status != "completed" {
		t.Errorf("Status = %q", v.Status)
	}
	if v.ArtifactCount != 3 {
		t.Errorf("ArtifactCount = %d", v.ArtifactCount)
	}
	if !strings.Contains(v.Duration, "45s") {
		t.Errorf("Duration = %q, want it to contain 45s", v.Duration)
	}
}

func TestMetadataArtifactToView(t *testing.T) {
	id := uuid.MustParse("55555555-5555-5555-5555-555555555555")
	a := &metadata.Artifact{
		ID:             id,
		JobID:          uuid.New(),
		Filename:       "vacation.jpg",
		MIME:           "image/jpeg",
		SizeBytes:      1500,
		SHA256:         []byte{0xaa, 0xbb, 0xcc, 0xdd},
		StrippedSHA256: []byte{0x11, 0x22, 0x33, 0x44},
		Extracted: map[string]any{
			"Camera": "Pixel",
			"GPS":    "40,-3",
		},
		CreatedAt: time.Now(),
	}
	v := metadataArtifactToView(a)
	if !v.StrippedAvailable {
		t.Error("expected StrippedAvailable to be true")
	}
	if v.DownloadURL == "" {
		t.Error("expected DownloadURL to be set when stripped is available")
	}
	if !strings.HasSuffix(v.DownloadURL, "/stripped") {
		t.Errorf("DownloadURL = %q, expected to end with /stripped", v.DownloadURL)
	}
	if v.SizeHuman != "1.5 KB" {
		t.Errorf("SizeHuman = %q", v.SizeHuman)
	}
	if len(v.Extracted) != 2 {
		t.Errorf("Extracted fields = %v", v.Extracted)
	}
	if v.ExtractedJSON == "" {
		t.Error("ExtractedJSON should be populated")
	}
}

func TestMetadataAdapter_Disabled(t *testing.T) {
	a := &metadataAdapter{svc: nil, enabled: false}
	if a.IsEnabled() {
		t.Fatal("disabled adapter should report IsEnabled() == false")
	}
	_, err := a.CreateJob(context.Background(), MetadataCreateJobInput{})
	if err == nil {
		t.Fatal("expected error when service is nil")
	}
	jobs, err := a.ListJobs(context.Background(), 5)
	if err != nil || jobs != nil {
		t.Errorf("ListJobs() = (%v, %v), want (nil, nil)", jobs, err)
	}
}
