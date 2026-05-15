// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
	dnstpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/dns"
)

// requireDNSSvc returns the DNS service or renders a "not configured"
// page. v26.5.1 nil-safe pattern, matching the other ported modules.
func (h *Handler) requireDNSSvc(w http.ResponseWriter, r *http.Request) *dnssvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.dnsSvc != nil {
		return reg.dnsSvc
	}
	pageData := h.prepareTemplPageData(r, "DNS Providers", "dns")
	h.renderTempl(w, r, dnstpl.Empty(dnstpl.EmptyData{
		PageData: pageData,
		Message:  "The DNS module is not enabled in this build (typically the data encryption key is unset).",
	}))
	return nil
}

func (h *Handler) getDNSHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

func (h *Handler) dnsUserUUID(r *http.Request) *uuid.UUID {
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// ============================================================================
// Providers
// ============================================================================

// DNSProvidersTempl renders /dns.
func (h *Handler) DNSProvidersTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getDNSHostID(r)
	pageData := h.prepareTemplPageData(r, "DNS Providers", "dns")

	providers, err := svc.ListProviders(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load providers: "+err.Error())
		return
	}
	views := make([]dnstpl.ProviderView, 0, len(providers))
	for _, p := range providers {
		recs, _ := svc.ListRecords(ctx, p.ID)
		views = append(views, providerToView(p, len(recs)))
	}
	h.renderTempl(w, r, dnstpl.ProviderList(dnstpl.ProviderListData{
		PageData:     pageData,
		Providers:    views,
		Capabilities: capabilitiesToViews(svc.SupportedProviders()),
	}))
}

// DNSProviderNewTempl renders /dns/new.
func (h *Handler) DNSProviderNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New DNS Provider", "dns")
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := caps[0]
	if k := r.URL.Query().Get("kind"); k != "" {
		for _, c := range caps {
			if c.Kind == k {
				selected = c
				break
			}
		}
	}
	h.renderTempl(w, r, dnstpl.ProviderNew(dnstpl.ProviderFormData{
		PageData:     pageData,
		IsEdit:       false,
		Provider:     dnstpl.ProviderView{ProviderKind: selected.Kind, Enabled: true},
		Capabilities: caps,
		Selected:     selected,
	}))
}

// DNSProviderCreateTempl handles POST /dns.
func (h *Handler) DNSProviderCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	hostID := h.getDNSHostID(r)
	userID := h.dnsUserUUID(r)

	kind := models.DNSProviderKind(r.FormValue("provider_kind"))
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := selectedCapability(caps, string(kind))

	creds := collectCredentialsJSON(r, selected.CredentialFields)
	cfg := collectConfigMap(r, selected.ConfigFields)

	in := dnssvc.CreateProviderInput{
		HostID:       hostID,
		Name:         r.FormValue("name"),
		ProviderKind: kind,
		Description:  r.FormValue("description"),
		Enabled:      r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on",
		Credentials:  creds,
		Config:       cfg,
	}
	if _, err := svc.CreateProvider(r.Context(), in, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New DNS Provider", "dns")
		h.renderTempl(w, r, dnstpl.ProviderNew(dnstpl.ProviderFormData{
			PageData:     pageData,
			IsEdit:       false,
			Provider:     dnstpl.ProviderView{Name: in.Name, ProviderKind: string(kind), Description: in.Description, Enabled: in.Enabled},
			Capabilities: caps,
			Selected:     selected,
			Error:        "Failed to create provider: " + err.Error(),
		}))
		return
	}
	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// DNSProviderEditTempl renders /dns/{id}/edit.
func (h *Handler) DNSProviderEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	p, err := svc.GetProvider(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not found", "Provider not found")
		return
	}
	pageData := h.prepareTemplPageData(r, "Edit DNS Provider", "dns")
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := selectedCapability(caps, string(p.ProviderKind))
	h.renderTempl(w, r, dnstpl.ProviderEdit(dnstpl.ProviderFormData{
		PageData:     pageData,
		IsEdit:       true,
		Provider:     providerToView(p, 0),
		Capabilities: caps,
		Selected:     selected,
	}))
}

// DNSProviderUpdateTempl handles POST /dns/{id}.
func (h *Handler) DNSProviderUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	userID := h.dnsUserUUID(r)
	p, err := svc.GetProvider(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not found", "Provider not found")
		return
	}
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := selectedCapability(caps, string(p.ProviderKind))

	creds := collectCredentialsJSON(r, selected.CredentialFields)
	if isEmptyCredentials(creds, selected.CredentialFields) {
		creds = nil
	}
	cfg := collectConfigMap(r, selected.ConfigFields)

	in := dnssvc.UpdateProviderInput{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Enabled:     r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on",
		Credentials: creds,
		Config:      cfg,
	}
	if _, err := svc.UpdateProvider(r.Context(), id, in, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Update failed: "+err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%s", id), http.StatusSeeOther)
}

// DNSProviderDeleteTempl handles POST /dns/{id}/delete.
func (h *Handler) DNSProviderDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	userID := h.dnsUserUUID(r)
	if err := svc.DeleteProvider(r.Context(), id, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Delete failed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// DNSProviderDetailTempl renders /dns/{id}.
func (h *Handler) DNSProviderDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	p, err := svc.GetProvider(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not found", "Provider not found")
		return
	}
	recs, _ := svc.ListRecords(r.Context(), id)
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := selectedCapability(caps, string(p.ProviderKind))
	pageData := h.prepareTemplPageData(r, "DNS · "+p.Name, "dns")
	h.renderTempl(w, r, dnstpl.ProviderDetail(dnstpl.ProviderDetailData{
		PageData: pageData,
		Provider: providerToView(p, len(recs)),
		Records:  recordsToViews(recs),
		Selected: selected,
	}))
}

// ============================================================================
// Records
// ============================================================================

// DNSRecordsTempl renders /dns/records.
func (h *Handler) DNSRecordsTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	hostID := h.getDNSHostID(r)
	pageData := h.prepareTemplPageData(r, "DNS Records", "dns")

	providers, _ := svc.ListProviders(r.Context(), hostID)
	pvViews := make([]dnstpl.ProviderView, 0, len(providers))
	for _, p := range providers {
		pvViews = append(pvViews, providerToView(p, 0))
	}
	recs, err := svc.ListHostRecords(r.Context(), hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load records: "+err.Error())
		return
	}
	h.renderTempl(w, r, dnstpl.Records(dnstpl.RecordsAcrossProvidersData{
		PageData:  pageData,
		Providers: pvViews,
		Records:   recordsToViews(recs),
	}))
}

// DNSRecordNewTempl renders /dns/{id}/records/new.
func (h *Handler) DNSRecordNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	p, err := svc.GetProvider(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not found", "Provider not found")
		return
	}
	caps := capabilitiesToViews(svc.SupportedProviders())
	selected := selectedCapability(caps, string(p.ProviderKind))
	pageData := h.prepareTemplPageData(r, "New DNS Record", "dns")
	h.renderTempl(w, r, dnstpl.RecordNew(dnstpl.RecordNewData{
		PageData: pageData,
		Provider: providerToView(p, 0),
		Selected: selected,
	}))
}

// DNSRecordCreateTempl handles POST /dns/{id}/records.
func (h *Handler) DNSRecordCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	providerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad provider ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	ttl := 300
	if v, convErr := strconv.Atoi(r.FormValue("ttl")); convErr == nil && v > 0 {
		ttl = v
	}
	in := dnssvc.RecordInput{
		Name:    r.FormValue("name"),
		Type:    models.DNSRecordType(r.FormValue("type")),
		Content: r.FormValue("content"),
		TTL:     ttl,
	}
	if _, err := svc.CreateRecord(r.Context(), providerID, in, h.dnsUserUUID(r)); err != nil {
		p, _ := svc.GetProvider(r.Context(), providerID)
		caps := capabilitiesToViews(svc.SupportedProviders())
		var selected dnstpl.CapabilityView
		if p != nil {
			selected = selectedCapability(caps, string(p.ProviderKind))
		}
		pageData := h.prepareTemplPageData(r, "New DNS Record", "dns")
		view := dnstpl.ProviderView{ID: providerID.String()}
		if p != nil {
			view = providerToView(p, 0)
		}
		h.renderTempl(w, r, dnstpl.RecordNew(dnstpl.RecordNewData{
			PageData: pageData,
			Provider: view,
			Selected: selected,
			Error:    "Failed to create record: " + err.Error(),
		}))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/%s", providerID), http.StatusSeeOther)
}

// DNSRecordDeleteTempl handles POST /dns/records/{id}/delete.
func (h *Handler) DNSRecordDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad record ID")
		return
	}
	if err := svc.DeleteRecord(r.Context(), id, h.dnsUserUUID(r)); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Delete failed: "+err.Error())
		return
	}
	target := r.Referer()
	if target == "" {
		target = "/dns"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// ============================================================================
// ACME orders
// ============================================================================

// DNSACMETempl renders /dns/acme.
func (h *Handler) DNSACMETempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	hostID := h.getDNSHostID(r)
	providers, _ := svc.ListProviders(r.Context(), hostID)
	nameByID := make(map[uuid.UUID]string, len(providers))
	for _, p := range providers {
		nameByID[p.ID] = p.Name
	}
	orders, err := svc.ListOrders(r.Context(), hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load orders: "+err.Error())
		return
	}
	views := make([]dnstpl.OrderView, 0, len(orders))
	for _, o := range orders {
		views = append(views, orderToView(o, nameByID[o.ProviderID]))
	}
	pageData := h.prepareTemplPageData(r, "DNS · ACME orders", "dns")
	h.renderTempl(w, r, dnstpl.Orders(dnstpl.OrderListData{PageData: pageData, Orders: views}))
}

// DNSACMEDetailTempl renders /dns/acme/{id}.
func (h *Handler) DNSACMEDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad order ID")
		return
	}
	order, err := svc.GetOrder(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not found", "Order not found")
		return
	}
	provider, _ := svc.GetProvider(r.Context(), order.ProviderID)
	providerName := ""
	if provider != nil {
		providerName = provider.Name
	}
	audit, _ := svc.ListOrderAudit(r.Context(), id)
	pageData := h.prepareTemplPageData(r, "DNS · ACME order", "dns")
	h.renderTempl(w, r, dnstpl.OrderDetail(dnstpl.OrderDetailData{
		PageData: pageData,
		Order:    orderToView(order, providerName),
		Audit:    auditToViews(audit),
	}))
}

// DNSACMEProcessTempl handles POST /dns/acme/{id}/process.
func (h *Handler) DNSACMEProcessTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Bad order ID")
		return
	}
	if _, err := svc.ProcessOrder(r.Context(), id); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Process failed: "+err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns/acme/%s", id), http.StatusSeeOther)
}

// ============================================================================
// Supported providers + Audit
// ============================================================================

// DNSSupportedTempl renders /dns/supported.
func (h *Handler) DNSSupportedTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "DNS · Capability matrix", "dns")
	h.renderTempl(w, r, dnstpl.Supported(dnstpl.CapabilityPageData{
		PageData:     pageData,
		Capabilities: capabilitiesToViews(svc.SupportedProviders()),
	}))
}

// DNSAuditTempl renders /dns/audit.
func (h *Handler) DNSAuditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	hostID := h.getDNSHostID(r)
	page := 0
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n >= 0 {
			page = n
		}
	}
	limit := 50
	entries, total, err := svc.ListAudit(r.Context(), hostID, limit, page*limit)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load audit log: "+err.Error())
		return
	}
	pageData := h.prepareTemplPageData(r, "DNS · Audit", "dns")
	h.renderTempl(w, r, dnstpl.Audit(dnstpl.AuditPageData{
		PageData: pageData,
		Entries:  auditToViews(entries),
		Total:    total,
		Page:     page,
		PageSize: limit,
	}))
}

// ============================================================================
// Adapters
// ============================================================================

func providerToView(p *models.DNSProvider, recordCount int) dnstpl.ProviderView {
	if p == nil {
		return dnstpl.ProviderView{}
	}
	return dnstpl.ProviderView{
		ID:           p.ID.String(),
		Name:         p.Name,
		ProviderKind: string(p.ProviderKind),
		KindLabel:    providerKindLabel(p.ProviderKind),
		Description:  p.Description,
		Enabled:      p.Enabled,
		RecordCount:  recordCount,
		CreatedAt:    p.CreatedAt.Format("2006-01-02 15:04"),
	}
}

func providerKindLabel(k models.DNSProviderKind) string {
	switch k {
	case models.DNSProviderKindCloudflare:
		return "Cloudflare"
	case models.DNSProviderKindRoute53:
		return "AWS Route 53"
	case models.DNSProviderKindDigitalOcean:
		return "DigitalOcean"
	case models.DNSProviderKindRFC2136:
		return "RFC 2136"
	}
	return string(k)
}

func capabilitiesToViews(caps []dnssvc.Capabilities) []dnstpl.CapabilityView {
	out := make([]dnstpl.CapabilityView, 0, len(caps))
	for _, c := range caps {
		recs := make([]dnstpl.CapabilityRecord, 0, len(c.Records))
		for _, r := range c.Records {
			recs = append(recs, dnstpl.CapabilityRecord{
				Type:      string(r.Type),
				Read:      r.Read,
				Write:     r.Write,
				UpdateTTL: r.UpdateTTL,
			})
		}
		credFields := make([]dnstpl.CredentialFieldView, 0, len(c.CredentialFields))
		for _, f := range c.CredentialFields {
			credFields = append(credFields, dnstpl.CredentialFieldView{
				Key: f.Key, Label: f.Label, Required: f.Required, Secret: f.Secret, Description: f.Description,
			})
		}
		cfgFields := make([]dnstpl.ConfigFieldView, 0, len(c.ConfigFields))
		for _, f := range c.ConfigFields {
			cfgFields = append(cfgFields, dnstpl.ConfigFieldView{
				Key: f.Key, Label: f.Label, Type: f.Type, Description: f.Description,
				Default: defaultToString(f.Default),
			})
		}
		out = append(out, dnstpl.CapabilityView{
			Kind:             string(c.Kind),
			DisplayName:      c.DisplayName,
			Description:      c.Description,
			Records:          recs,
			CredentialFields: credFields,
			ConfigFields:     cfgFields,
		})
	}
	return out
}

func recordsToViews(recs []*models.DNSRecord) []dnstpl.RecordView {
	out := make([]dnstpl.RecordView, 0, len(recs))
	for _, r := range recs {
		out = append(out, dnstpl.RecordView{
			ID:         r.ID.String(),
			ProviderID: r.ProviderID.String(),
			Name:       r.Name,
			Type:       string(r.Type),
			Content:    r.Content,
			TTL:        r.TTL,
			ManagedBy:  r.ManagedBy,
			IsManual:   r.IsManual(),
			CreatedAt:  r.CreatedAt.Format("2006-01-02 15:04"),
		})
	}
	return out
}

func orderToView(o *models.DNSACMEOrder, providerName string) dnstpl.OrderView {
	v := dnstpl.OrderView{
		ID:             o.ID.String(),
		Domain:         o.Domain,
		ProviderID:     o.ProviderID.String(),
		ProviderName:   providerName,
		State:          string(o.State),
		StateLabel:     orderStateLabel(o.State),
		StateClass:     orderStateClass(o.State),
		ErrorMsg:       o.ErrorMsg,
		ChallengeFQDN:  o.ChallengeFQDN,
		ChallengeValue: o.ChallengeValue,
		PropChecks:     o.PropagationCheckCount,
		CreatedAt:      o.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if o.LastCheckAt != nil {
		v.LastCheck = o.LastCheckAt.Format("2006-01-02 15:04:05")
	}
	if o.CompletedAt != nil {
		v.CompletedAt = o.CompletedAt.Format("2006-01-02 15:04:05")
	}
	return v
}

func orderStateLabel(s models.ACMEOrderState) string {
	switch s {
	case models.ACMEOrderStatePending:
		return "Pending"
	case models.ACMEOrderStateDropping:
		return "Dropping TXT"
	case models.ACMEOrderStatePropagating:
		return "Propagating"
	case models.ACMEOrderStateReady:
		return "Ready"
	case models.ACMEOrderStateCompleting:
		return "Cleaning up"
	case models.ACMEOrderStateCompleted:
		return "Completed"
	case models.ACMEOrderStateFailed:
		return "Failed"
	}
	return string(s)
}

func orderStateClass(s models.ACMEOrderState) string {
	switch s {
	case models.ACMEOrderStateCompleted:
		return "badge badge-success"
	case models.ACMEOrderStateFailed:
		return "badge badge-danger"
	case models.ACMEOrderStateReady:
		return "badge badge-info"
	}
	return "badge badge-warning"
}

func auditToViews(entries []*models.DNSAuditLog) []dnstpl.AuditEntryView {
	out := make([]dnstpl.AuditEntryView, 0, len(entries))
	for _, e := range entries {
		v := dnstpl.AuditEntryView{
			When:         e.CreatedAt.Format("2006-01-02 15:04:05"),
			Action:       e.Action,
			ResourceType: e.ResourceType,
			ResourceName: e.ResourceName,
			Details:      e.Details,
		}
		if e.UserID != nil {
			v.UserID = e.UserID.String()
		}
		out = append(out, v)
	}
	return out
}

// ============================================================================
// Form parsing helpers
// ============================================================================

func selectedCapability(caps []dnstpl.CapabilityView, kind string) dnstpl.CapabilityView {
	for _, c := range caps {
		if c.Kind == kind {
			return c
		}
	}
	if len(caps) > 0 {
		return caps[0]
	}
	return dnstpl.CapabilityView{}
}

// collectCredentialsJSON builds the credential JSON blob from form
// fields named cred_<key>. Empty values are skipped so the service
// layer can treat the blob as "no rotation requested" on update.
func collectCredentialsJSON(r *http.Request, fields []dnstpl.CredentialFieldView) []byte {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(r.FormValue("cred_" + f.Key))
		if v == "" {
			continue
		}
		out[f.Key] = v
	}
	if len(out) == 0 {
		return []byte{}
	}
	buf, _ := json.Marshal(out)
	return buf
}

func collectConfigMap(r *http.Request, fields []dnstpl.ConfigFieldView) map[string]any {
	cfg := make(map[string]any, len(fields))
	for _, f := range fields {
		v := r.FormValue("cfg_" + f.Key)
		if v == "" {
			continue
		}
		switch f.Type {
		case "int":
			if n, err := strconv.Atoi(v); err == nil {
				cfg[f.Key] = n
				continue
			}
		case "bool":
			cfg[f.Key] = v == "true" || v == "on"
			continue
		}
		cfg[f.Key] = v
	}
	return cfg
}

func isEmptyCredentials(blob []byte, fields []dnstpl.CredentialFieldView) bool {
	if len(blob) == 0 {
		return true
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	_ = fields
	return false
}

func defaultToString(def any) string {
	if def == nil {
		return ""
	}
	switch v := def.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return fmt.Sprintf("%v", def)
}
