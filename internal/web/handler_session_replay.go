// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SessionReplayPage renders the session replay player page.
// GET /session-replay/{id}
func (h *Handler) SessionReplayPage(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		h.setFlash(w, r, "error", "Missing session ID")
		h.redirect(w, r, "/")
		return
	}

	if h.recordingSvc == nil {
		h.setFlash(w, r, "error", "Session recording is not available")
		h.redirect(w, r, "/")
		return
	}

	id, err := uuid.Parse(sessionID)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid session ID")
		h.redirect(w, r, "/")
		return
	}

	// Verify the recording file exists on disk
	path := h.recordingSvc.GetRecordingPath(id)
	if _, err := os.Stat(path); err != nil {
		h.setFlash(w, r, "error", "Recording not found")
		h.redirect(w, r, "/")
		return
	}

	// Render a minimal replay page with inline asciinema player
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Session Replay</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.css">
<style>body { background: #0d1117; margin: 0; padding: 20px; }
.header { color: #c9d1d9; font-family: sans-serif; margin-bottom: 16px; }
.header a { color: #58a6ff; text-decoration: none; }
</style>
</head>
<body>
<div class="header">
  <a href="javascript:history.back()">&#8592; Back</a>
  <h2>Session Replay</h2>
</div>
<div id="player"></div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.min.js"></script>
<script>
AsciinemaPlayer.create('/session-replay/` + sessionID + `/data', document.getElementById('player'), {
  theme: 'monokai',
  fit: 'width',
  autoPlay: true,
});
</script>
</body>
</html>`))
}

// SessionReplayData serves the recording data (decompressed asciicast).
// GET /session-replay/{id}/data
func (h *Handler) SessionReplayData(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		h.jsonError(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	if h.recordingSvc == nil {
		h.jsonError(w, "Session recording is not available", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(sessionID)
	if err != nil {
		h.jsonError(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	path := h.recordingSvc.GetRecordingPath(id)

	f, err := os.Open(path)
	if err != nil {
		h.jsonError(w, "Recording not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	// Decompress gzip
	gz, err := gzip.NewReader(f)
	if err != nil {
		h.jsonError(w, "Failed to read recording", http.StatusInternalServerError)
		return
	}
	defer gz.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.Copy(w, gz)
}
