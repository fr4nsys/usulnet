// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
)

// DNSService is the narrow interface this handler depends on,
// satisfied by *dnssvc.Service. v26.2.7 had no API handler — this is
// a fresh boundary built per session-10.
type DNSService interface {
	SupportedProviders() []dnssvc.Capabilities

	ListProviders(ctx context.Context, hostID uuid.UUID) ([]*models.DNSProvider, error)
	GetProvider(ctx context.Context, id uuid.UUID) (*models.DNSProvider, error)
	CreateProvider(ctx context.Context, in dnssvc.CreateProviderInput, userID *uuid.UUID) (*models.DNSProvider, error)
	UpdateProvider(ctx context.Context, id uuid.UUID, in dnssvc.UpdateProviderInput, userID *uuid.UUID) (*models.DNSProvider, error)
	DeleteProvider(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error

	ListRecords(ctx context.Context, providerID uuid.UUID) ([]*models.DNSRecord, error)
	ListHostRecords(ctx context.Context, hostID uuid.UUID) ([]*models.DNSRecord, error)
	CreateRecord(ctx context.Context, providerID uuid.UUID, in dnssvc.RecordInput, userID *uuid.UUID) (*models.DNSRecord, error)
	DeleteRecord(ctx context.Context, recordID uuid.UUID, userID *uuid.UUID) error

	ListOrders(ctx context.Context, hostID uuid.UUID) ([]*models.DNSACMEOrder, error)
	GetOrder(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error)
	StartOrder(ctx context.Context, req dnssvc.ACMEOrderRequest) (*models.DNSACMEOrder, error)
	ProcessOrder(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error)
	MarkOrderCompleted(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error)
	FailOrder(ctx context.Context, id uuid.UUID, reason string) (*models.DNSACMEOrder, error)
	ListOrderAudit(ctx context.Context, orderID uuid.UUID) ([]*models.DNSAuditLog, error)
	ListAudit(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error)
}

// DNSHandler exposes the DNS REST API. The handler is nil-safe: when
// svc is nil, every endpoint replies 503 service_unavailable so the
// route mounting code in router.go does not have to reason about
// boot-time gaps.
type DNSHandler struct {
	BaseHandler
	svc      DNSService
	hostIDFn func(*http.Request) uuid.UUID
}

// NewDNSHandler builds a DNS handler.
func NewDNSHandler(svc DNSService, hostIDFn func(*http.Request) uuid.UUID, log *logger.Logger) *DNSHandler {
	return &DNSHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		hostIDFn:    hostIDFn,
	}
}

// Routes mounts /api/v1/dns/*. The caller is responsible for placing
// the subtree behind the JWT/API-key middleware.
func (h *DNSHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.With(middleware.RequireViewer).Get("/supported-providers", h.SupportedProviders)

	r.Route("/providers", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListProviders)
		r.With(middleware.RequireOperator).Post("/", h.CreateProvider)
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetProvider)
			r.With(middleware.RequireOperator).Put("/", h.UpdateProvider)
			r.With(middleware.RequireOperator).Delete("/", h.DeleteProvider)
		})
	})

	r.Route("/records", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListRecords)
		r.With(middleware.RequireOperator).Post("/", h.CreateRecord)
		r.With(middleware.RequireOperator).Delete("/{id}", h.DeleteRecord)
	})

	r.Route("/acme-orders", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListOrders)
		r.With(middleware.RequireOperator).Post("/", h.StartOrder)
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetOrder)
			r.With(middleware.RequireOperator).Post("/process", h.ProcessOrder)
			r.With(middleware.RequireOperator).Post("/complete", h.MarkOrderCompleted)
			r.With(middleware.RequireOperator).Post("/fail", h.FailOrder)
			r.With(middleware.RequireViewer).Get("/audit", h.OrderAudit)
		})
	})

	r.With(middleware.RequireViewer).Get("/audit", h.ListAudit)

	return r
}

// ============================================================================
// Supported providers (capability matrix)
// ============================================================================

// SupportedProviders returns the static plugin capability matrix.
func (h *DNSHandler) SupportedProviders(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	h.OK(w, h.svc.SupportedProviders())
}

// ============================================================================
// Providers
// ============================================================================

// ProviderResponse is the JSON shape returned to clients. Credentials
// are intentionally omitted — once persisted the operator can rotate
// but never read them back.
type ProviderResponse struct {
	ID           uuid.UUID              `json:"id"`
	HostID       uuid.UUID              `json:"host_id"`
	Name         string                 `json:"name"`
	ProviderKind models.DNSProviderKind `json:"provider_kind"`
	Enabled      bool                   `json:"enabled"`
	Description  string                 `json:"description"`
	Config       map[string]any         `json:"config"`
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
}

func toProviderResponse(p *models.DNSProvider) ProviderResponse {
	return ProviderResponse{
		ID:           p.ID,
		HostID:       p.HostID,
		Name:         p.Name,
		ProviderKind: p.ProviderKind,
		Enabled:      p.Enabled,
		Description:  p.Description,
		Config:       p.Config,
		CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    p.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// CreateProviderRequest is the body of POST /api/v1/dns/providers.
// Credentials is the raw plaintext JSON the operator pastes; the
// service encrypts it before persistence.
type CreateProviderRequest struct {
	HostID       string                 `json:"host_id,omitempty"`
	Name         string                 `json:"name" validate:"required,min=1,max=255"`
	ProviderKind models.DNSProviderKind `json:"provider_kind" validate:"required"`
	Description  string                 `json:"description,omitempty"`
	Enabled      bool                   `json:"enabled"`
	Credentials  json.RawMessage        `json:"credentials" validate:"required"`
	Config       map[string]any         `json:"config,omitempty"`
}

// ListProviders handles GET /api/v1/dns/providers.
func (h *DNSHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	list, err := h.svc.ListProviders(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	out := make([]ProviderResponse, len(list))
	for i, p := range list {
		out[i] = toProviderResponse(p)
	}
	h.OK(w, out)
}

// GetProvider handles GET /api/v1/dns/providers/{id}.
func (h *DNSHandler) GetProvider(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	p, err := h.svc.GetProvider(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, toProviderResponse(p))
}

// CreateProvider handles POST /api/v1/dns/providers.
func (h *DNSHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateProviderRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	in := dnssvc.CreateProviderInput{
		HostID:       hostID,
		Name:         req.Name,
		ProviderKind: req.ProviderKind,
		Description:  req.Description,
		Enabled:      req.Enabled,
		Credentials:  req.Credentials,
		Config:       req.Config,
	}
	p, err := h.svc.CreateProvider(r.Context(), in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.Created(w, toProviderResponse(p))
}

// UpdateProviderRequest is the body of PUT /api/v1/dns/providers/{id}.
// Credentials is optional — leave empty to keep the existing value.
type UpdateProviderRequest struct {
	Name        string          `json:"name" validate:"required,min=1,max=255"`
	Description string          `json:"description,omitempty"`
	Enabled     bool            `json:"enabled"`
	Credentials json.RawMessage `json:"credentials,omitempty"`
	Config      map[string]any  `json:"config,omitempty"`
}

// UpdateProvider handles PUT /api/v1/dns/providers/{id}.
func (h *DNSHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req UpdateProviderRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	in := dnssvc.UpdateProviderInput{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     req.Enabled,
		Credentials: req.Credentials,
		Config:      req.Config,
	}
	p, err := h.svc.UpdateProvider(r.Context(), id, in, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, toProviderResponse(p))
}

// DeleteProvider handles DELETE /api/v1/dns/providers/{id}.
func (h *DNSHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	if err := h.svc.DeleteProvider(r.Context(), id, nilableUUID(actor)); err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.NoContent(w)
}

// ============================================================================
// Records
// ============================================================================

// ListRecords handles GET /api/v1/dns/records?provider_id=...&host=...
// Either provider_id or host_id (resolved from header/query) must be
// supplied; provider_id wins when both are set.
func (h *DNSHandler) ListRecords(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	if pid := h.QueryParam(r, "provider_id"); pid != "" {
		id, err := uuid.Parse(pid)
		if err != nil {
			h.BadRequest(w, "invalid provider_id format")
			return
		}
		recs, err := h.svc.ListRecords(r.Context(), id)
		if err != nil {
			h.HandleError(w, mapDNSError(err))
			return
		}
		h.OK(w, recs)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	recs, err := h.svc.ListHostRecords(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, recs)
}

// CreateRecordRequest is the body of POST /api/v1/dns/records.
type CreateRecordRequest struct {
	ProviderID string               `json:"provider_id" validate:"required,uuid"`
	Name       string               `json:"name" validate:"required,min=1,max=512"`
	Type       models.DNSRecordType `json:"type" validate:"required"`
	Content    string               `json:"content" validate:"required"`
	TTL        int                  `json:"ttl"`
}

// CreateRecord handles POST /api/v1/dns/records.
func (h *DNSHandler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req CreateRecordRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	pid, err := uuid.Parse(req.ProviderID)
	if err != nil {
		h.BadRequest(w, "invalid provider_id format")
		return
	}
	actor, _ := h.GetUserID(r)
	rec, err := h.svc.CreateRecord(r.Context(), pid, dnssvc.RecordInput{
		Name: req.Name, Type: req.Type, Content: req.Content, TTL: req.TTL,
	}, nilableUUID(actor))
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.Created(w, rec)
}

// DeleteRecord handles DELETE /api/v1/dns/records/{id}.
func (h *DNSHandler) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	actor, _ := h.GetUserID(r)
	if err := h.svc.DeleteRecord(r.Context(), id, nilableUUID(actor)); err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.NoContent(w)
}

// ============================================================================
// ACME orders
// ============================================================================

// StartOrderRequest is the body of POST /api/v1/dns/acme-orders.
type StartOrderRequest struct {
	HostID         string `json:"host_id,omitempty"`
	ProviderID     string `json:"provider_id" validate:"required,uuid"`
	Domain         string `json:"domain"      validate:"required"`
	ChallengeValue string `json:"challenge_value" validate:"required"`
}

// StartOrder handles POST /api/v1/dns/acme-orders.
func (h *DNSHandler) StartOrder(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	var req StartOrderRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	hostID, err := h.resolveHostIDFromBody(r, req.HostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	pid, err := uuid.Parse(req.ProviderID)
	if err != nil {
		h.BadRequest(w, "invalid provider_id format")
		return
	}
	order, err := h.svc.StartOrder(r.Context(), dnssvc.ACMEOrderRequest{
		HostID: hostID, ProviderID: pid, Domain: req.Domain, ChallengeValue: req.ChallengeValue,
	})
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.Created(w, order)
}

// ListOrders handles GET /api/v1/dns/acme-orders.
func (h *DNSHandler) ListOrders(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	orders, err := h.svc.ListOrders(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, orders)
}

// GetOrder handles GET /api/v1/dns/acme-orders/{id}.
func (h *DNSHandler) GetOrder(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	order, err := h.svc.GetOrder(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, order)
}

// ProcessOrder handles POST /api/v1/dns/acme-orders/{id}/process.
// Manually nudges the state machine; useful for resuming a stuck
// order via the UI.
func (h *DNSHandler) ProcessOrder(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	order, err := h.svc.ProcessOrder(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, order)
}

// MarkOrderCompleted handles POST /api/v1/dns/acme-orders/{id}/complete.
// Called by the proxy module after the CA validates the challenge.
func (h *DNSHandler) MarkOrderCompleted(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	order, err := h.svc.MarkOrderCompleted(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, order)
}

// FailOrderRequest carries the diagnostic the proxy module records
// when the CA rejects the challenge.
type FailOrderRequest struct {
	Reason string `json:"reason" validate:"required,max=4096"`
}

// FailOrder handles POST /api/v1/dns/acme-orders/{id}/fail.
func (h *DNSHandler) FailOrder(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	var req FailOrderRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}
	order, err := h.svc.FailOrder(r.Context(), id, req.Reason)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, order)
}

// OrderAudit handles GET /api/v1/dns/acme-orders/{id}/audit.
func (h *DNSHandler) OrderAudit(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	entries, err := h.svc.ListOrderAudit(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, entries)
}

// ============================================================================
// Audit
// ============================================================================

// ListAudit handles GET /api/v1/dns/audit.
func (h *DNSHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.serviceUnavailable(w)
		return
	}
	hostID, err := h.resolveHostID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	limit := h.QueryParamInt(r, "limit", 50)
	offset := h.QueryParamInt(r, "offset", 0)
	entries, total, err := h.svc.ListAudit(r.Context(), hostID, limit, offset)
	if err != nil {
		h.HandleError(w, mapDNSError(err))
		return
	}
	h.OK(w, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func (h *DNSHandler) serviceUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.ServiceUnavailable("dns service is not configured"))
}

func (h *DNSHandler) resolveHostID(r *http.Request) (uuid.UUID, error) {
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

func (h *DNSHandler) resolveHostIDFromBody(r *http.Request, bodyHostID string) (uuid.UUID, error) {
	if bodyHostID != "" {
		id, err := uuid.Parse(bodyHostID)
		if err != nil {
			return uuid.Nil, apierrors.InvalidInput("invalid host_id format")
		}
		return id, nil
	}
	return h.resolveHostID(r)
}

// mapDNSError translates dns service errors to API errors. The
// service surfaces ErrProviderNotFound and friends as plain errors;
// we promote them so the API returns the right HTTP code.
func mapDNSError(err error) error {
	switch {
	case stderrors.Is(err, dnssvc.ErrProviderNotFound):
		return apierrors.NotFound("dns provider")
	case stderrors.Is(err, dnssvc.ErrInvalidCredentials):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, dnssvc.ErrZoneNotFound):
		return apierrors.InvalidInput(err.Error())
	case stderrors.Is(err, dnssvc.ErrRecordNotFound):
		return apierrors.NotFound("dns record")
	case stderrors.Is(err, dnssvc.ErrPropagationTimeout):
		return apierrors.NewError(http.StatusGatewayTimeout, "PROPAGATION_TIMEOUT", err.Error())
	case stderrors.Is(err, dnssvc.ErrStateConflict):
		return apierrors.NewError(http.StatusConflict, "STATE_CONFLICT", err.Error())
	}
	return err
}
