// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	stderrors "errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	calendarsvc "github.com/fr4nsys/usulnet/internal/services/calendar"
)

// CalendarService is the narrow interface this handler depends on,
// satisfied by *calendar.Service. Declaring it here lets the handler be
// unit-tested with a mock without importing the concrete service.
// v26.2.7 had a handler at the API surface too but no contracted
// interface — this is the v26.5.1 boundary.
type CalendarService interface {
	Create(ctx context.Context, hostID uuid.UUID, input models.CreateCalendarEventInput, userID *uuid.UUID) (*models.CalendarEvent, error)
	Get(ctx context.Context, id uuid.UUID) (*models.CalendarEvent, error)
	Update(ctx context.Context, id uuid.UUID, input models.UpdateCalendarEventInput) (*models.CalendarEvent, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListEvents(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]*models.CalendarEvent, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.CalendarStats, error)
	ExportICS(ctx context.Context, hostID uuid.UUID) ([]byte, error)
	Sources() []string
}

// CalendarHandler handles /api/v1/calendar/* requests. The svc field is
// nil-safe: when it is nil every handler returns 503 service_unavailable
// so the routes still mount cleanly during early app boot.
type CalendarHandler struct {
	BaseHandler
	svc      CalendarService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewCalendarHandler creates a new calendar handler.
func NewCalendarHandler(svc CalendarService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *CalendarHandler {
	return &CalendarHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes returns the chi router for /api/v1/calendar.
// Read endpoints are viewer+, mutations are operator+.
func (h *CalendarHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.With(middleware.RequireViewer).Get("/events", h.ListEvents)
	r.With(middleware.RequireOperator).Post("/events", h.CreateEvent)

	r.Route("/events/{id}", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.GetEvent)
		r.With(middleware.RequireOperator).Put("/", h.UpdateEvent)
		r.With(middleware.RequireOperator).Delete("/", h.DeleteEvent)
	})

	r.With(middleware.RequireViewer).Get("/stats", h.GetStats)
	r.With(middleware.RequireViewer).Get("/sources", h.ListSources)
	r.With(middleware.RequireViewer).Get("/export.ics", h.ExportICS)

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// CreateCalendarEventRequest is the body for POST /api/v1/calendar/events.
type CreateCalendarEventRequest struct {
	HostID      string `json:"host_id,omitempty" validate:"omitempty,uuid"`
	Kind        string `json:"kind" validate:"required,oneof=maintenance backup deploy job alert note"`
	Title       string `json:"title" validate:"required,min=1,max=255"`
	Description string `json:"description,omitempty" validate:"omitempty,max=4096"`
	Location    string `json:"location,omitempty" validate:"omitempty,max=255"`
	URL         string `json:"url,omitempty" validate:"omitempty,url,max=2048"`
	StartsAt    string `json:"starts_at" validate:"required"`
	EndsAt      string `json:"ends_at" validate:"required"`
	AllDay      bool   `json:"all_day,omitempty"`
}

// UpdateCalendarEventRequest is the body for PUT /api/v1/calendar/events/{id}.
// All fields are optional; only the supplied ones are patched.
type UpdateCalendarEventRequest struct {
	Kind        *string `json:"kind,omitempty" validate:"omitempty,oneof=maintenance backup deploy job alert note"`
	Title       *string `json:"title,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=4096"`
	Location    *string `json:"location,omitempty" validate:"omitempty,max=255"`
	URL         *string `json:"url,omitempty" validate:"omitempty,url,max=2048"`
	StartsAt    *string `json:"starts_at,omitempty"`
	EndsAt      *string `json:"ends_at,omitempty"`
	AllDay      *bool   `json:"all_day,omitempty"`
}

// CalendarEventResponse is the API view of a calendar event.
type CalendarEventResponse struct {
	ID          string  `json:"id"`
	HostID      string  `json:"host_id"`
	Source      string  `json:"source"`
	Kind        string  `json:"kind"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Location    string  `json:"location,omitempty"`
	URL         string  `json:"url,omitempty"`
	StartsAt    string  `json:"starts_at"`
	EndsAt      string  `json:"ends_at"`
	AllDay      bool    `json:"all_day"`
	ExternalID  string  `json:"external_id,omitempty"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
	UpdatedAt   string  `json:"updated_at,omitempty"`
}

// CalendarStatsResponse is the API view of CalendarStats.
type CalendarStatsResponse struct {
	Total       int `json:"total"`
	Maintenance int `json:"maintenance"`
	Backup      int `json:"backup"`
	Deploy      int `json:"deploy"`
	Job         int `json:"job"`
	Alert       int `json:"alert"`
	Note        int `json:"note"`
}

// CalendarSourcesResponse advertises the registered event sources.
type CalendarSourcesResponse struct {
	Sources []string `json:"sources"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListEvents handles GET /api/v1/calendar/events?from=...&to=....
func (h *CalendarHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	from, to, err := parseRangeQuery(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	events, err := h.svc.ListEvents(r.Context(), hostID, from, to)
	if err != nil {
		h.HandleError(w, mapCalendarError(err))
		return
	}
	resp := make([]CalendarEventResponse, len(events))
	for i, e := range events {
		resp[i] = toCalendarEventResponse(e)
	}
	h.OK(w, resp)
}

// CreateEvent handles POST /api/v1/calendar/events.
func (h *CalendarHandler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateCalendarEventRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	starts, err := parseTimestamp(req.StartsAt, "starts_at")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	ends, err := parseTimestamp(req.EndsAt, "ends_at")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	actor, _ := h.GetUserID(r)
	in := models.CreateCalendarEventInput{
		Kind:        models.CalendarEventKind(req.Kind),
		Title:       req.Title,
		Description: req.Description,
		Location:    req.Location,
		URL:         req.URL,
		StartsAt:    starts,
		EndsAt:      ends,
		AllDay:      req.AllDay,
	}

	event, err := h.svc.Create(r.Context(), hostID, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapCalendarError(err))
		return
	}
	h.Created(w, toCalendarEventResponse(event))
}

// GetEvent handles GET /api/v1/calendar/events/{id}.
func (h *CalendarHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	event, err := h.svc.Get(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapCalendarError(err))
		return
	}
	h.OK(w, toCalendarEventResponse(event))
}

// UpdateEvent handles PUT /api/v1/calendar/events/{id}.
func (h *CalendarHandler) UpdateEvent(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateCalendarEventRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	in := models.UpdateCalendarEventInput{
		Title:       req.Title,
		Description: req.Description,
		Location:    req.Location,
		URL:         req.URL,
		AllDay:      req.AllDay,
	}
	if req.Kind != nil {
		k := models.CalendarEventKind(*req.Kind)
		in.Kind = &k
	}
	if req.StartsAt != nil {
		ts, err := parseTimestamp(*req.StartsAt, "starts_at")
		if err != nil {
			h.HandleError(w, err)
			return
		}
		in.StartsAt = &ts
	}
	if req.EndsAt != nil {
		ts, err := parseTimestamp(*req.EndsAt, "ends_at")
		if err != nil {
			h.HandleError(w, err)
			return
		}
		in.EndsAt = &ts
	}

	event, err := h.svc.Update(r.Context(), id, in)
	if err != nil {
		h.HandleError(w, mapCalendarError(err))
		return
	}
	h.OK(w, toCalendarEventResponse(event))
}

// DeleteEvent handles DELETE /api/v1/calendar/events/{id}.
func (h *CalendarHandler) DeleteEvent(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		h.HandleError(w, mapCalendarError(err))
		return
	}
	h.NoContent(w)
}

// GetStats handles GET /api/v1/calendar/stats.
func (h *CalendarHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	s, err := h.svc.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	h.OK(w, CalendarStatsResponse{
		Total:       s.Total,
		Maintenance: s.Maintenance,
		Backup:      s.Backup,
		Deploy:      s.Deploy,
		Job:         s.Job,
		Alert:       s.Alert,
		Note:        s.Note,
	})
}

// ListSources handles GET /api/v1/calendar/sources.
func (h *CalendarHandler) ListSources(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	h.OK(w, CalendarSourcesResponse{Sources: h.svc.Sources()})
}

// ExportICS handles GET /api/v1/calendar/export.ics.
//
// Returns an RFC 5545 .ics document with text/calendar Content-Type so
// clients (Apple Calendar, Google Calendar, Thunderbird) can subscribe
// to the URL directly.
func (h *CalendarHandler) ExportICS(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	body, err := h.svc.ExportICS(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="usulnet-calendar.ics"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		h.logger.Warn("calendar: failed to write ICS body", "error", err)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func (h *CalendarHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("calendar service is not configured"))
}

func (h *CalendarHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
	if h.hostIDFn != nil {
		if id := h.hostIDFn(r); id != uuid.Nil {
			return id, nil
		}
	}
	if q := h.QueryParam(r, "host_id"); q != "" {
		id, err := uuid.Parse(q)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	if hdr := r.Header.Get("X-Host-ID"); hdr != "" {
		id, err := uuid.Parse(hdr)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid X-Host-ID format")
		}
		return id, nil
	}
	return uuid.Nil, apierrors.MissingField("host_id")
}

func (h *CalendarHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

// parseRangeQuery extracts ?from=…&to=… or falls back to "now" and "now+31d".
func parseRangeQuery(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	defaultFrom := now.AddDate(0, 0, -1)
	defaultTo := now.AddDate(0, 0, calendarsvc.DefaultRangeDays)

	from := defaultFrom
	to := defaultTo
	if q := r.URL.Query().Get("from"); q != "" {
		t, err := parseTimestamp(q, "from")
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = t
	}
	if q := r.URL.Query().Get("to"); q != "" {
		t, err := parseTimestamp(q, "to")
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		to = t
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, apierrors.InvalidInput("to must be after from")
	}
	return from, to, nil
}

// parseTimestamp accepts RFC 3339 and date-only inputs.
func parseTimestamp(s, field string) (time.Time, error) {
	if s == "" {
		return time.Time{}, apierrors.MissingField(field)
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, apierrors.InvalidInput("invalid " + field + " format (expected RFC3339 or YYYY-MM-DD)")
}

// mapCalendarError translates service-level errors to API errors.
func mapCalendarError(err error) error {
	switch {
	case stderrors.Is(err, calendarsvc.ErrInvalidInput):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, calendarsvc.ErrInvalidRange):
		return apierrors.InvalidInput(err.Error())
	}
	return err
}

// toCalendarEventResponse converts a model into an API view.
func toCalendarEventResponse(e *models.CalendarEvent) CalendarEventResponse {
	resp := CalendarEventResponse{
		ID:          e.ID.String(),
		HostID:      e.HostID.String(),
		Source:      string(e.Source),
		Kind:        string(e.Kind),
		Title:       e.Title,
		Description: e.Description,
		Location:    e.Location,
		URL:         e.URL,
		StartsAt:    e.StartsAt.Format(time.RFC3339),
		EndsAt:      e.EndsAt.Format(time.RFC3339),
		AllDay:      e.AllDay,
		ExternalID:  e.ExternalID,
	}
	if e.CreatedBy != nil {
		s := e.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if !e.CreatedAt.IsZero() {
		resp.CreatedAt = e.CreatedAt.Format(time.RFC3339)
	}
	if !e.UpdatedAt.IsZero() {
		resp.UpdatedAt = e.UpdatedAt.Format(time.RFC3339)
	}
	return resp
}
