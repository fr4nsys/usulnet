// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/hosts"
)

// HostCreateFormTempl renders the "Add Node" form page.
func (h *Handler) HostCreateFormTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Add Node", "nodes")
	data := hosts.CreateData{
		PageData: pageData,
	}
	h.renderTempl(w, r, hosts.Create(data))
}

// HostEditFormTempl renders the "Edit Node" form page.
func (h *Handler) HostEditFormTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	if _, err := uuid.Parse(idStr); err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid Host ID", "The host ID format is invalid.")
		return
	}

	host, err := h.services.Hosts().Get(ctx, idStr)
	if err != nil || host == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Host Not Found", "The host could not be found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Node: "+host.Name, "nodes")

	editHost := hosts.EditHost{
		ID:           host.ID,
		Name:         host.Name,
		DisplayName:  host.DisplayName,
		EndpointType: host.EndpointType,
		EndpointURL:  host.Endpoint,
		Status:       host.Status,
		TLSEnabled:   host.TLSEnabled,
	}

	data := hosts.EditData{
		PageData: pageData,
		Host:     editHost,
	}
	h.renderTempl(w, r, hosts.Edit(data))
}

// hostCreateForm captures the host create inputs. endpoint_type
// defaults to "local" after binding when blank; tls_enabled uses
// the "true" literal that the existing form posts (not the HTML
// "on" default), so we read it via the helper's flexible bool
// parser.
type hostCreateForm struct {
	Name         string `form:"name" validate:"required,min=1,max=200"`
	EndpointType string `form:"endpoint_type"`
	EndpointURL  string `form:"endpoint_url"`
	TLSEnabled   bool   `form:"tls_enabled"`
}

// HostCreateTempl handles POST /nodes/create - creates a new host.
func (h *Handler) HostCreateTempl(w http.ResponseWriter, r *http.Request) {
	var form hostCreateForm
	if msg := BindForm(r, &form); msg != "" {
		h.renderCreateError(w, r, msg)
		return
	}

	endpointType := form.EndpointType
	if endpointType == "" {
		endpointType = "local"
	}

	hv := &HostView{
		Name:         form.Name,
		EndpointType: endpointType,
		Endpoint:     form.EndpointURL,
		TLSEnabled:   form.TLSEnabled,
	}

	hostID, err := h.services.Hosts().Create(r.Context(), hv)
	if err != nil {
		h.renderCreateError(w, r, "Failed to create node: "+err.Error())
		return
	}

	// For agent hosts, generate a token and redirect to edit page to show it
	if endpointType == "agent" {
		token, err := h.services.Hosts().GenerateAgentToken(r.Context(), hostID)
		if err != nil {
			// Host created but token generation failed - redirect to edit page
			http.Redirect(w, r, "/nodes/"+hostID+"/edit", http.StatusSeeOther)
			return
		}
		h.renderEditWithToken(w, r, hostID, token)
		return
	}

	http.Redirect(w, r, "/nodes/"+hostID, http.StatusSeeOther)
}

// hostUpdateForm captures the host update inputs. action is a
// mode field — "regenerate_token" routes to the token-rotation
// branch; the empty value runs the normal update path.
type hostUpdateForm struct {
	Action      string `form:"action"`
	DisplayName string `form:"display_name"`
	EndpointURL string `form:"endpoint_url"`
	TLSEnabled  bool   `form:"tls_enabled"`
}

// HostUpdateTempl handles POST /nodes/{id} - updates a host.
func (h *Handler) HostUpdateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	if _, err := uuid.Parse(idStr); err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid Host ID", "The host ID format is invalid.")
		return
	}

	var form hostUpdateForm
	if msg := BindForm(r, &form); msg != "" {
		h.renderEditError(w, r, idStr, msg)
		return
	}

	// Handle token regeneration
	if form.Action == "regenerate_token" {
		token, err := h.services.Hosts().GenerateAgentToken(ctx, idStr)
		if err != nil {
			h.renderEditError(w, r, idStr, "Failed to regenerate token: "+err.Error())
			return
		}
		h.renderEditWithToken(w, r, idStr, token)
		return
	}

	hv := &HostView{
		ID:          idStr,
		DisplayName: form.DisplayName,
		Endpoint:    form.EndpointURL,
		TLSEnabled:  form.TLSEnabled,
	}

	if err := h.services.Hosts().Update(ctx, hv); err != nil {
		h.renderEditError(w, r, idStr, "Failed to update node: "+err.Error())
		return
	}

	http.Redirect(w, r, "/nodes/"+idStr, http.StatusSeeOther)
}

// HostRemoveTempl handles DELETE /nodes/{id} - deletes a host.
func (h *Handler) HostRemoveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	if err := h.services.Hosts().Remove(ctx, idStr); err != nil {
		w.Header().Set("HX-Redirect", "/nodes")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// For HTMX requests, send redirect header
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/nodes")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

// renderCreateError re-renders the create form with an error message.
func (h *Handler) renderCreateError(w http.ResponseWriter, r *http.Request, errMsg string) {
	pageData := h.prepareTemplPageData(r, "Add Node", "nodes")
	data := hosts.CreateData{
		PageData:     pageData,
		Error:        errMsg,
		Name:         r.FormValue("name"),
		EndpointType: r.FormValue("endpoint_type"),
		EndpointURL:  r.FormValue("endpoint_url"),
		TLSEnabled:   r.FormValue("tls_enabled") == "true",
	}
	h.renderTempl(w, r, hosts.Create(data))
}

// renderEditError re-renders the edit form with an error message.
func (h *Handler) renderEditError(w http.ResponseWriter, r *http.Request, hostID, errMsg string) {
	ctx := r.Context()
	host, err := h.services.Hosts().Get(ctx, hostID)
	if err != nil || host == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Host Not Found", "The host could not be found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Node: "+host.Name, "nodes")
	editHost := hosts.EditHost{
		ID:           host.ID,
		Name:         host.Name,
		DisplayName:  host.DisplayName,
		EndpointType: host.EndpointType,
		EndpointURL:  host.Endpoint,
		Status:       host.Status,
		TLSEnabled:   host.TLSEnabled,
	}

	data := hosts.EditData{
		PageData: pageData,
		Error:    errMsg,
		Host:     editHost,
	}
	h.renderTempl(w, r, hosts.Edit(data))
}

// renderEditWithToken renders the edit form with a freshly generated agent token.
func (h *Handler) renderEditWithToken(w http.ResponseWriter, r *http.Request, hostID, token string) {
	ctx := r.Context()
	host, err := h.services.Hosts().Get(ctx, hostID)
	if err != nil || host == nil {
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Node: "+host.Name, "nodes")
	editHost := hosts.EditHost{
		ID:           host.ID,
		Name:         host.Name,
		DisplayName:  host.DisplayName,
		EndpointType: host.EndpointType,
		EndpointURL:  host.Endpoint,
		Status:       host.Status,
		TLSEnabled:   host.TLSEnabled,
	}

	data := hosts.EditData{
		PageData:   pageData,
		Host:       editHost,
		AgentToken: token,
	}
	h.renderTempl(w, r, hosts.Edit(data))
}

// SwitchHost handles GET /switch-host/{id} - switches the active host in the session.
func (h *Handler) SwitchHost(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "id")
	if _, err := uuid.Parse(hostID); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Save to session
	session, err := h.sessionStore.Get(r, CookieSession)
	if err != nil || session == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if session.Values == nil {
		session.Values = make(map[string]interface{})
	}
	session.Values["active_host_id"] = hostID
	if err := h.sessionStore.Save(r, w, session); err != nil {
		h.logger.Warn("failed to save session after host switch", "error", err)
	}

	// Redirect back to the referring page, or dashboard
	referer := r.Header.Get("Referer")
	if referer != "" {
		http.Redirect(w, r, referer, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
