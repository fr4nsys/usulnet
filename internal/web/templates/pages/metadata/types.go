// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package metadata contains server-side rendered templates for the
// metadata hygiene workflow (v26.5.0).
package metadata

import (
	"github.com/fr4nsys/usulnet/internal/web/templates/layouts"
)

// UploadData backs /recon/metadata.
type UploadData struct {
	PageData   layouts.PageData
	RecentJobs []JobView
}

// JobDetailData backs /recon/metadata/jobs/{id}.
type JobDetailData struct {
	PageData  layouts.PageData
	Job       JobView
	Artifacts []ArtifactView
}

// JobView is one metadata-job row.
type JobView struct {
	ID            string
	Source        string
	SourceRef     string
	Mode          string
	Status        string
	ArtifactCount int
	Error         string
	StartedAt     string
	FinishedAt    string
	Duration      string
	CreatedAt     string
}

// ArtifactView is one processed file in a job.
type ArtifactView struct {
	ID                string
	Filename          string
	MIME              string
	SizeHuman         string
	SHA256Hex         string
	StrippedSHA256Hex string
	StrippedAvailable bool
	DownloadURL       string
	Fields            []MetadataField
	ExtractedJSON     string
}

// MetadataField is one extracted key/value.
type MetadataField struct {
	Key   string
	Value string
}

// StatusClass returns Tailwind classes for the job-status badge,
// reusing the recon scan palette.
func StatusClass(status string) string {
	switch status {
	case "completed":
		return "text-green-400 bg-green-500/10 border-green-500/20"
	case "running":
		return "text-primary-400 bg-primary-500/10 border-primary-500/20"
	case "queued":
		return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
	case "failed":
		return "text-red-400 bg-red-500/10 border-red-500/20"
	default:
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	}
}
