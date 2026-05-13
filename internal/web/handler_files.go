// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ContainerBrowseAPI handles file browsing via web session auth.
// GET /containers/{id}/files/api/browse/*
func (h *Handler) ContainerBrowseAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	files, err := h.services.Containers().BrowseFiles(r.Context(), containerID, path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path":  path,
		"files": files,
	})
}

// ContainerReadFileAPI reads a file from a container via web session auth.
// GET /containers/{id}/files/api/file/*
func (h *Handler) ContainerReadFileAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	content, err := h.services.Containers().ReadFile(r.Context(), containerID, path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(content)
}

// ContainerDownloadFileAPI downloads a raw file from a container.
// GET /containers/{id}/files/api/download/*
func (h *Handler) ContainerDownloadFileAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	content, err := h.services.Containers().ReadFile(r.Context(), containerID, path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if content.Binary {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}

	// Extract filename from path
	filename := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		filename = path[idx+1:]
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write([]byte(content.Content))
}

// ContainerWriteFileAPI writes a file in a container via web session auth.
// PUT /containers/{id}/files/api/file/*
func (h *Handler) ContainerWriteFileAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := h.services.Containers().WriteFile(r.Context(), containerID, path, body.Content); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// ContainerDeleteFileAPI deletes a file in a container via web session auth.
// DELETE /containers/{id}/files/api/file/*
func (h *Handler) ContainerDeleteFileAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	recursive := r.URL.Query().Get("recursive") == "true"

	if err := h.services.Containers().DeleteFile(r.Context(), containerID, path, recursive); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// ContainerMkdirAPI creates a directory in a container via web session auth.
// POST /containers/{id}/files/api/mkdir/*
func (h *Handler) ContainerMkdirAPI(w http.ResponseWriter, r *http.Request) {
	containerID := chi.URLParam(r, "id")
	path := chi.URLParam(r, "*")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if err := h.services.Containers().CreateDirectory(r.Context(), containerID, path); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}
