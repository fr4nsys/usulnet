// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	proxy "github.com/fr4nsys/usulnet/internal/web/templates/pages/proxy"
)

// ============================================================================
// Proxy Setup Handlers (NPM Connection Management)
// ============================================================================

// ProxySetupTempl renders the NPM connection setup page.
func (h *Handler) ProxySetupTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")

	data := proxy.SetupData{
		PageData: pageData,
	}

	conn, err := h.services.Proxy().GetConnection(ctx)
	if err == nil && conn != nil {
		data.Connected = true
		data.BaseURL = conn.BaseURL
		data.AdminEmail = conn.AdminEmail
		data.ConnID = conn.ID
		data.Health = conn.HealthStatus
	}

	h.renderTempl(w, r, proxy.Setup(data))
}

// ProxySetupSaveTempl handles POST /proxy/setup to create or update NPM connection.
func (h *Handler) ProxySetupSaveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	baseURL := r.FormValue("base_url")
	email := r.FormValue("admin_email")
	password := r.FormValue("admin_password")

	user := GetUserFromContext(ctx)
	userID := ""
	if user != nil {
		userID = user.ID
	}

	// Check if connection already exists
	conn, _ := h.services.Proxy().GetConnection(ctx)
	if conn != nil {
		// Update existing
		var pURL, pEmail, pPwd *string
		if baseURL != "" {
			pURL = &baseURL
		}
		if email != "" {
			pEmail = &email
		}
		if password != "" {
			pPwd = &password
		}
		if err := h.services.Proxy().UpdateConnectionConfig(ctx, conn.ID, pURL, pEmail, pPwd, nil, userID); err != nil {
			slog.Error("Failed to update NPM connection", "error", err)
			pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")
			data := proxy.SetupData{
				PageData:   pageData,
				Connected:  true,
				BaseURL:    conn.BaseURL,
				AdminEmail: conn.AdminEmail,
				ConnID:     conn.ID,
				Error:      "Failed to update connection: " + err.Error(),
			}
			h.renderTempl(w, r, proxy.Setup(data))
			return
		}
	} else {
		// Create new
		if baseURL == "" || email == "" || password == "" {
			pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")
			data := proxy.SetupData{
				PageData: pageData,
				BaseURL:  baseURL,
				AdminEmail: email,
				Error:    "All fields are required for new connection",
			}
			h.renderTempl(w, r, proxy.Setup(data))
			return
		}
		if err := h.services.Proxy().SetupConnection(ctx, baseURL, email, password, userID); err != nil {
			slog.Error("Failed to setup NPM connection", "error", err)
			pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")
			data := proxy.SetupData{
				PageData:   pageData,
				BaseURL:    baseURL,
				AdminEmail: email,
				Error:      "Failed to connect: " + err.Error(),
			}
			h.renderTempl(w, r, proxy.Setup(data))
			return
		}
	}

	http.Redirect(w, r, "/proxy/setup", http.StatusSeeOther)
}

// ProxySetupDeleteTempl handles POST /proxy/setup/delete to remove NPM connection.
func (h *Handler) ProxySetupDeleteTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	conn, err := h.services.Proxy().GetConnection(ctx)
	if err != nil || conn == nil {
		http.Redirect(w, r, "/proxy/setup", http.StatusSeeOther)
		return
	}

	if err := h.services.Proxy().DeleteConnection(ctx, conn.ID); err != nil {
		slog.Error("Failed to delete NPM connection", "error", err)
	}

	http.Redirect(w, r, "/proxy/setup", http.StatusSeeOther)
}

// ProxySetupTestTempl handles POST /proxy/setup/test to test NPM connection.
func (h *Handler) ProxySetupTestTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")

	data := proxy.SetupData{
		PageData: pageData,
	}

	conn, err := h.services.Proxy().GetConnection(ctx)
	if err != nil || conn == nil {
		data.Error = "No NPM connection configured"
		h.renderTempl(w, r, proxy.Setup(data))
		return
	}

	data.Connected = true
	data.BaseURL = conn.BaseURL
	data.AdminEmail = conn.AdminEmail
	data.ConnID = conn.ID

	// Try to sync (which tests the connection)
	if err := h.services.Proxy().Sync(ctx); err != nil {
		data.Error = "Connection test failed: " + err.Error()
		data.Health = "unhealthy"
	} else {
		data.Success = "Connection test successful"
		data.Health = "healthy"
	}

	h.renderTempl(w, r, proxy.Setup(data))
}

// ============================================================================
// Proxy Host CRUD Handlers
// ============================================================================

// ProxyNewTempl renders the new proxy host form.
func (h *Handler) ProxyNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Proxy Host", "proxy")
	connected := h.services.Proxy().IsConnected(r.Context())

	data := proxy.NewData{
		PageData:  pageData,
		Connected: connected,
	}
	h.renderTempl(w, r, proxy.New(data))
}

// ProxyHostCreateTempl handles POST /proxy/hosts to create a new proxy host.
func (h *Handler) ProxyHostCreateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	domain := r.FormValue("domain")
	forwardHost := r.FormValue("forward_host")
	forwardPort, _ := strconv.Atoi(r.FormValue("forward_port"))
	sslEnabled := r.FormValue("ssl_enabled") == "true"

	if domain == "" || forwardHost == "" || forwardPort == 0 {
		pageData := h.prepareTemplPageData(r, "New Proxy Host", "proxy")
		data := proxy.NewData{
			PageData:  pageData,
			Connected: h.services.Proxy().IsConnected(ctx),
			Error:     "Domain, forward host, and forward port are required",
		}
		h.renderTempl(w, r, proxy.New(data))
		return
	}

	host := &ProxyHostView{
		Domain:      domain,
		ForwardHost: forwardHost,
		ForwardPort: forwardPort,
		SSLEnabled:  sslEnabled,
		Enabled:     true,
	}

	if err := h.services.Proxy().CreateHost(ctx, host); err != nil {
		slog.Error("Failed to create proxy host", "domain", domain, "error", err)
		pageData := h.prepareTemplPageData(r, "New Proxy Host", "proxy")
		data := proxy.NewData{
			PageData:  pageData,
			Connected: h.services.Proxy().IsConnected(ctx),
			Error:     "Failed to create proxy host: " + err.Error(),
		}
		h.renderTempl(w, r, proxy.New(data))
		return
	}

	http.Redirect(w, r, "/proxy", http.StatusSeeOther)
}

// ProxyDetailTempl renders proxy host detail page.
func (h *Handler) ProxyDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	pageData := h.prepareTemplPageData(r, "Proxy Host", "proxy")
	connected := h.services.Proxy().IsConnected(ctx)

	host, err := h.services.Proxy().GetHost(ctx, id)
	if err != nil || host == nil {
		slog.Error("Failed to get proxy host", "id", id, "error", err)
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	data := proxy.DetailData{
		PageData:  pageData,
		Connected: connected,
		Host: proxy.ProxyHost{
			ID:            idStr,
			DomainName:    host.Domain,
			ForwardHost:   host.ForwardHost,
			ForwardPort:   host.ForwardPort,
			SSLEnabled:    host.SSLEnabled,
			Enabled:       host.Enabled,
			ContainerName: host.Container,
		},
	}
	h.renderTempl(w, r, proxy.Detail(data))
}

// ProxyEditTempl renders the edit proxy host form.
func (h *Handler) ProxyEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Proxy Host", "proxy")
	connected := h.services.Proxy().IsConnected(ctx)

	host, err := h.services.Proxy().GetHost(ctx, id)
	if err != nil || host == nil {
		slog.Error("Failed to get proxy host for edit", "id", id, "error", err)
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	data := proxy.EditData{
		PageData:  pageData,
		Connected: connected,
		Host: proxy.ProxyHost{
			ID:            idStr,
			DomainName:    host.Domain,
			ForwardHost:   host.ForwardHost,
			ForwardPort:   host.ForwardPort,
			SSLEnabled:    host.SSLEnabled,
			Enabled:       host.Enabled,
			ContainerName: host.Container,
		},
	}
	h.renderTempl(w, r, proxy.Edit(data))
}

// ProxyHostUpdateTempl handles POST /proxy/hosts/{id} to update a proxy host.
func (h *Handler) ProxyHostUpdateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Check for _method=DELETE override
	if r.FormValue("_method") == "DELETE" {
		h.proxyHostDeleteByID(w, r, id)
		return
	}

	domain := r.FormValue("domain")
	forwardHost := r.FormValue("forward_host")
	forwardPort, _ := strconv.Atoi(r.FormValue("forward_port"))
	sslEnabled := r.FormValue("ssl_enabled") == "true"
	enabled := r.FormValue("enabled") == "true"

	host := &ProxyHostView{
		ID:          id,
		Domain:      domain,
		ForwardHost: forwardHost,
		ForwardPort: forwardPort,
		SSLEnabled:  sslEnabled,
		Enabled:     enabled,
	}

	if err := h.services.Proxy().UpdateHost(ctx, host); err != nil {
		slog.Error("Failed to update proxy host", "id", id, "error", err)
		pageData := h.prepareTemplPageData(r, "Edit Proxy Host", "proxy")
		data := proxy.EditData{
			PageData:  pageData,
			Connected: h.services.Proxy().IsConnected(ctx),
			Host: proxy.ProxyHost{
				ID:          idStr,
				DomainName:  domain,
				ForwardHost: forwardHost,
				ForwardPort: forwardPort,
				SSLEnabled:  sslEnabled,
				Enabled:     enabled,
			},
			Error: "Failed to update: " + err.Error(),
		}
		h.renderTempl(w, r, proxy.Edit(data))
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/proxy/%s", idStr), http.StatusSeeOther)
}

// ProxyHostDeleteTempl handles DELETE /proxy/hosts/{id}.
func (h *Handler) ProxyHostDeleteTempl(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}
	h.proxyHostDeleteByID(w, r, id)
}

func (h *Handler) proxyHostDeleteByID(w http.ResponseWriter, r *http.Request, id int) {
	ctx := r.Context()
	if err := h.services.Proxy().RemoveHost(ctx, id); err != nil {
		slog.Error("Failed to delete proxy host", "id", id, "error", err)
	}

	// HTMX request: return empty for swap
	if r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/proxy", http.StatusSeeOther)
}

// ProxyHostEnableTempl handles POST /proxy/hosts/{id}/enable.
func (h *Handler) ProxyHostEnableTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	if err := h.services.Proxy().EnableHost(ctx, id); err != nil {
		slog.Error("Failed to enable proxy host", "id", id, "error", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/proxy/%s", idStr), http.StatusSeeOther)
}

// ProxyHostDisableTempl handles POST /proxy/hosts/{id}/disable.
func (h *Handler) ProxyHostDisableTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	if err := h.services.Proxy().DisableHost(ctx, id); err != nil {
		slog.Error("Failed to disable proxy host", "id", id, "error", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/proxy/%s", idStr), http.StatusSeeOther)
}

// ProxySyncTempl handles POST /proxy/sync to trigger NPM sync.
func (h *Handler) ProxySyncTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.services.Proxy().Sync(ctx); err != nil {
		slog.Error("Failed to sync NPM", "error", err)
	}

	http.Redirect(w, r, "/proxy", http.StatusSeeOther)
}
