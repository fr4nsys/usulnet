// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	yarasvc "github.com/fr4nsys/usulnet/internal/services/yara"
)

// YARAService is the narrow surface this handler depends on, satisfied
// by *yara.Service. Declared here so the handler can be unit-tested
// with a mock without importing the concrete service.
type YARAService interface {
	Scan(ctx context.Context, target yarasvc.ScanTarget, ruleset string) (*yarasvc.Result, error)
}

// YARAHandler serves /api/v1/yara/* and the container-scoped scan path
// at /api/v1/containers/{hostID}/{containerID}/yara-scan. svc is
// nil-safe; when it is nil every endpoint returns 503.
type YARAHandler struct {
	BaseHandler
	svc YARAService
}

// NewYARAHandler wires the handler. log may be nil — BaseHandler
// substitutes a no-op logger.
func NewYARAHandler(svc YARAService, log *logger.Logger) *YARAHandler {
	return &YARAHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
	}
}

// Routes returns the chi router for /api/v1/yara.
//
//	GET  /rulesets             → list embedded ruleset names (viewer+)
//	POST /scan                 → scan an arbitrary target (operator+)
//
// The container-scoped path `/api/v1/containers/{hostID}/{containerID}/
// yara-scan` is mounted elsewhere (api/router.go) so it composes with
// the existing /containers tree.
func (h *YARAHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.With(middleware.RequireViewer).Get("/rulesets", h.ListRulesets)
	r.With(middleware.RequireOperator).Post("/scan", h.Scan)
	return r
}

// ----------------------------------------------------------------------------
// DTOs
// ----------------------------------------------------------------------------

// ScanRequest is the body for POST /scan and the container-scoped
// POST /containers/{hostID}/{containerID}/yara-scan endpoint.
//
// For the container-scoped variant the route URL supplies the
// container ID; the body's ContainerID is ignored in that path so the
// URL is the source of truth.
type ScanRequest struct {
	Ruleset     string `json:"ruleset" validate:"required,min=1,max=255"`
	HostPath    string `json:"host_path,omitempty" validate:"omitempty,max=4096"`
	ContainerID string `json:"container_id,omitempty" validate:"omitempty,max=128"`
	Path        string `json:"path,omitempty" validate:"omitempty,max=4096"`
}

// MatchView is the API view of one yara hit.
type MatchView struct {
	Rule      string   `json:"rule"`
	Namespace string   `json:"namespace,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Target    string   `json:"target"`
}

// YARAScanResponse is the body of a successful scan.
type YARAScanResponse struct {
	Ruleset   string      `json:"ruleset"`
	Target    string      `json:"target"`
	Matches   []MatchView `json:"matches"`
	StartedAt string      `json:"started_at"`
	Duration  string      `json:"duration"`
	ExitCode  int         `json:"exit_code"`
}

// RulesetsResponse is the body of GET /rulesets.
type RulesetsResponse struct {
	Rulesets []string `json:"rulesets"`
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// ListRulesets handles GET /api/v1/yara/rulesets.
func (h *YARAHandler) ListRulesets(w http.ResponseWriter, _ *http.Request) {
	names, err := yarasvc.ListRulesets()
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, RulesetsResponse{Rulesets: names})
}

// Scan handles POST /api/v1/yara/scan — generic scan against either
// a host path or a (containerID + path) target supplied in the body.
func (h *YARAHandler) Scan(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailableYARA(w)
		return
	}
	var req ScanRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	target := yarasvc.ScanTarget{
		HostPath:    req.HostPath,
		ContainerID: req.ContainerID,
		Path:        req.Path,
	}
	res, err := h.svc.Scan(r.Context(), target, req.Ruleset)
	if err != nil {
		h.HandleError(w, mapYARAError(err))
		return
	}
	h.OK(w, toYARAScanResponse(res))
}

// ContainerScan handles POST /api/v1/containers/{hostID}/{containerID}/
// yara-scan. The container ID and path are URL-scoped (container ID
// from {containerID}, path from request body). The request body still
// supplies the ruleset.
func (h *YARAHandler) ContainerScan(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailableYARA(w)
		return
	}
	containerID := chi.URLParam(r, "containerID")
	if containerID == "" {
		h.HandleError(w, apierrors.MissingField("containerID"))
		return
	}
	var req ScanRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	if req.Path == "" {
		h.HandleError(w, apierrors.MissingField("path"))
		return
	}
	target := yarasvc.ScanTarget{
		ContainerID: containerID,
		Path:        req.Path,
	}
	res, err := h.svc.Scan(r.Context(), target, req.Ruleset)
	if err != nil {
		h.HandleError(w, mapYARAError(err))
		return
	}
	h.OK(w, toYARAScanResponse(res))
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (h *YARAHandler) serviceUnavailableYARA(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("yara service is not configured"))
}

func mapYARAError(err error) error {
	switch {
	case errors.Is(err, yarasvc.ErrInvalidTarget):
		return apierrors.InvalidInput(err.Error())
	case errors.Is(err, yarasvc.ErrUnknownRuleset):
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

func toYARAScanResponse(r *yarasvc.Result) YARAScanResponse {
	matches := make([]MatchView, len(r.Matches))
	for i, m := range r.Matches {
		matches[i] = MatchView{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Target:    m.Target,
		}
	}
	return YARAScanResponse{
		Ruleset:   r.Ruleset,
		Target:    r.Target,
		Matches:   matches,
		StartedAt: r.StartedAt.Format("2006-01-02T15:04:05Z07:00"),
		Duration:  r.Duration,
		ExitCode:  r.ExitCode,
	}
}
