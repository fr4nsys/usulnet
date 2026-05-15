// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dockerconfig contains the templ pages for the Docker engine
// configuration editor (v26.5.1 — ported from v26.2.7 as AGPL feature).
package dockerconfig

import "github.com/fr4nsys/usulnet/internal/web/templates/layouts"

// EditorData powers the editor.templ page.
type EditorData struct {
	PageData       layouts.PageData
	ConfigPath     string
	RawJSON        string
	ReloadTimeout  string
	Snapshots      []SnapshotView
	Flash          FlashMessage
	UnavailableMsg string
	LastApplied    *AppliedView
}

// HistoryData powers the history.templ page.
type HistoryData struct {
	PageData       layouts.PageData
	ConfigPath     string
	Snapshots      []SnapshotView
	Flash          FlashMessage
	UnavailableMsg string
}

// SnapshotView is the per-row view of a snapshot in the history list.
type SnapshotView struct {
	ID        string
	Size      string // human-readable
	Timestamp string // already formatted
}

// FlashMessage is the inline status banner. Type ∈ {"", success, warning, error}.
type FlashMessage struct {
	Type    string
	Message string
}

// AppliedView surfaces the last apply result on the editor page so the
// operator can see the rollback flag without leaving the page.
type AppliedView struct {
	SnapshotID    string
	ApplyMode     string
	ChangedFields []string
	Reloaded      bool
	RolledBack    bool
	RollbackError string
	Warning       string
}
