// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	dockerconfigsvc "github.com/fr4nsys/usulnet/internal/services/dockerconfig"
)

// DockerEngineService is the narrow interface this handler depends on,
// satisfied by *dockerconfig.Service. The boundary is named explicitly
// so the handler is unit-testable without importing the concrete
// service. v26.2.7 had no API handler — the web handler called the
// concrete service directly with a per-tab form-extraction path. v26.5.1
// flips that around: a single PUT replaces the seven-tab form and the
// web layer reuses this handler's request shape.
type DockerEngineService interface {
	Read(ctx context.Context) (*dockerconfigsvc.DaemonConfig, error)
	ReadRaw(ctx context.Context) (string, error)
	Apply(ctx context.Context, raw []byte, reason string) (*dockerconfigsvc.UpdateResult, error)
	Restore(ctx context.Context, snapshotID, reason string) (*dockerconfigsvc.UpdateResult, error)
	ListSnapshots(ctx context.Context) ([]dockerconfigsvc.Snapshot, error)
	ConfigPath() string
	ReloadTimeout() time.Duration
}

// DockerEngineHandler handles /api/v1/docker-engine/* requests. The
// svc field is nil-safe: a nil service flips every endpoint to a 503
// response so the routes still mount cleanly during early app boot
// (and in installs that decline to mount /etc/docker into the
// container).
type DockerEngineHandler struct {
	BaseHandler
	svc DockerEngineService
}

// NewDockerEngineHandler creates a new docker-engine handler.
func NewDockerEngineHandler(svc DockerEngineService, log *logger.Logger) *DockerEngineHandler {
	return &DockerEngineHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
	}
}

// Routes returns the chi router for /api/v1/docker-engine.
//
// All read endpoints are viewer+. Apply / Restore are admin-only — they
// touch the host's daemon configuration and can take the daemon
// offline. The caller mounts this subtree behind the JWT/API-key
// middleware in internal/api/router.go.
func (h *DockerEngineHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/config", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetConfig)
		r.With(middleware.RequireAdmin).Put("/", h.PutConfig)
		r.With(middleware.RequireViewer).Get("/history", h.ListHistory)
		r.With(middleware.RequireAdmin).Post("/restore/{snapshot_id}", h.Restore)
	})

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// DockerEngineConfigResponse is the body of GET /config.
type DockerEngineConfigResponse struct {
	Path          string                                 `json:"path"`
	RawJSON       string                                 `json:"raw_json"`
	Parsed        *dockerconfigsvc.DaemonConfig          `json:"parsed"`
	ReloadTimeout string                                 `json:"reload_timeout"`
	SettingsMeta  map[string]dockerconfigsvc.SettingMeta `json:"settings_meta"`
	HasFile       bool                                   `json:"has_file"`
}

// PutConfigRequest is the body of PUT /config. The raw JSON the
// operator typed in the editor is sent verbatim — we want the daemon's
// own parser to be the source of truth on what is valid.
type PutConfigRequest struct {
	Raw    json.RawMessage `json:"raw"`
	Reason string          `json:"reason,omitempty"`
}

// DockerEngineUpdateResponse is the body of PUT /config and the
// restore endpoint. Mirrors dockerconfig.UpdateResult so callers can
// render the rollback flag without parsing additional state.
type DockerEngineUpdateResponse struct {
	SnapshotID    string   `json:"snapshot_id,omitempty"`
	ApplyMode     string   `json:"apply_mode"`
	ChangedFields []string `json:"changed_fields"`
	Reloaded      bool     `json:"reloaded"`
	RolledBack    bool     `json:"rolled_back"`
	RollbackError string   `json:"rollback_error,omitempty"`
	Warning       string   `json:"warning,omitempty"`
}

// SnapshotResponse is the API view of a daemon.json snapshot.
type SnapshotResponse struct {
	ID        string `json:"id"`
	Size      int64  `json:"size"`
	Timestamp string `json:"timestamp"`
}

// HistoryResponse is the body of GET /config/history.
type HistoryResponse struct {
	Snapshots []SnapshotResponse `json:"snapshots"`
	Total     int                `json:"total"`
}

// ============================================================================
// Handlers
// ============================================================================

// GetConfig handles GET /api/v1/docker-engine/config.
func (h *DockerEngineHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	ctx := r.Context()
	raw, err := h.svc.ReadRaw(ctx)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	parsed, err := h.svc.Read(ctx)
	if err != nil {
		// Non-fatal: ReadRaw already succeeded; surface what we have.
		parsed = &dockerconfigsvc.DaemonConfig{}
	}
	h.OK(w, DockerEngineConfigResponse{
		Path:          h.svc.ConfigPath(),
		RawJSON:       raw,
		Parsed:        parsed,
		ReloadTimeout: h.svc.ReloadTimeout().String(),
		SettingsMeta:  dockerconfigsvc.AllSettingsMeta(),
		HasFile:       raw != "" && raw != "{}\n",
	})
}

// PutConfig handles PUT /api/v1/docker-engine/config. The body is the
// JSON the operator typed in the Monaco editor. The handler does not
// validate the JSON itself — it forwards the raw bytes to the service
// which parses, validates, snapshots, atomic-writes and reloads.
func (h *DockerEngineHandler) PutConfig(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	if r.Body == nil {
		h.BadRequest(w, "request body is empty")
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		h.BadRequest(w, "read body: "+err.Error())
		return
	}

	var req PutConfigRequest
	if jsonErr := json.Unmarshal(body, &req); jsonErr != nil {
		h.BadRequest(w, "invalid JSON envelope: "+jsonErr.Error())
		return
	}
	if len(req.Raw) == 0 {
		h.BadRequest(w, "raw is required")
		return
	}

	res, applyErr := h.svc.Apply(r.Context(), req.Raw, req.Reason)
	if applyErr != nil {
		// A rollback that succeeds still surfaces as an error from
		// Apply because the new config did not stick. We return 409
		// with the full UpdateResult so the UI can paint the rollback
		// banner without making a second call.
		if res != nil && res.RolledBack {
			h.JSON(w, http.StatusConflict, struct {
				Error  string                     `json:"error"`
				Result DockerEngineUpdateResponse `json:"result"`
			}{
				Error:  applyErr.Error(),
				Result: toUpdateResponse(res),
			})
			return
		}
		h.HandleError(w, applyErr)
		return
	}
	h.OK(w, toUpdateResponse(res))
}

// ListHistory handles GET /api/v1/docker-engine/config/history.
func (h *DockerEngineHandler) ListHistory(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	snaps, err := h.svc.ListSnapshots(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}
	out := make([]SnapshotResponse, len(snaps))
	for i, s := range snaps {
		out[i] = SnapshotResponse{
			ID:        s.ID,
			Size:      s.Size,
			Timestamp: s.Timestamp.UTC().Format(time.RFC3339),
		}
	}
	h.OK(w, HistoryResponse{Snapshots: out, Total: len(out)})
}

// Restore handles POST /api/v1/docker-engine/config/restore/{snapshot_id}.
func (h *DockerEngineHandler) Restore(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}
	id := chi.URLParam(r, "snapshot_id")
	if id == "" {
		h.BadRequest(w, "snapshot_id is required")
		return
	}
	res, err := h.svc.Restore(r.Context(), id, "api-restore")
	if err != nil {
		if res != nil && res.RolledBack {
			h.JSON(w, http.StatusConflict, struct {
				Error  string                     `json:"error"`
				Result DockerEngineUpdateResponse `json:"result"`
			}{
				Error:  err.Error(),
				Result: toUpdateResponse(res),
			})
			return
		}
		h.HandleError(w, err)
		return
	}
	h.OK(w, toUpdateResponse(res))
}

// ============================================================================
// Helpers
// ============================================================================

func (h *DockerEngineHandler) engineUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("docker engine config service is not configured (mount /etc/docker into the container)"))
}

func toUpdateResponse(r *dockerconfigsvc.UpdateResult) DockerEngineUpdateResponse {
	if r == nil {
		return DockerEngineUpdateResponse{}
	}
	return DockerEngineUpdateResponse{
		SnapshotID:    r.SnapshotID,
		ApplyMode:     string(r.ApplyMode),
		ChangedFields: r.ChangedFields,
		Reloaded:      r.Reloaded,
		RolledBack:    r.RolledBack,
		RollbackError: r.RollbackError,
		Warning:       r.WarningMsg,
	}
}
