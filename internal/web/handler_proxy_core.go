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

// requireProxySvc returns the Proxy service or renders a "not configured" error.
// Returns nil if the service is unavailable (caller should return early).
func (h *Handler) requireProxySvc(w http.ResponseWriter, r *http.Request) ProxyService {
	svc := h.services.Proxy()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Proxy Not Configured", "The reverse proxy service is not configured. Please configure it in your server settings.")
		return nil
	}
	return svc
}

// ============================================================================
// Proxy Setup Handlers (NPM Connection Management)
// ============================================================================

// ProxySetupTempl renders the NPM connection setup page.
func (h *Handler) ProxySetupTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		data := proxy.SetupData{
			PageData: pageData,
			Error:    "Proxy service is not configured",
		}
		h.renderTempl(w, r, proxy.Setup(data))
		return
	}

	data := proxy.SetupData{
		PageData:  pageData,
		ProxyMode: proxySvc.Mode(),
	}

	conn, err := proxySvc.GetConnection(ctx)
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
// proxySetupForm captures the NPM connection setup inputs.
// Required-ness is enforced after binding because the "update an
// existing connection" path accepts a partial form (the user only
// rotates the fields they want to change).
type proxySetupForm struct {
	BaseURL       string `form:"base_url"`
	AdminEmail    string `form:"admin_email"`
	AdminPassword string `form:"admin_password"`
}

func (h *Handler) ProxySetupSaveTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	var form proxySetupForm
	if msg := BindForm(r, &form); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	baseURL := form.BaseURL
	email := form.AdminEmail
	password := form.AdminPassword

	user := GetUserFromContext(ctx)
	userID := ""
	if user != nil {
		userID = user.ID
	}

	// Check if connection already exists
	conn, _ := proxySvc.GetConnection(ctx)
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
		if err := proxySvc.UpdateConnectionConfig(ctx, conn.ID, pURL, pEmail, pPwd, nil, userID); err != nil {
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
				PageData:   pageData,
				BaseURL:    baseURL,
				AdminEmail: email,
				Error:      "All fields are required for new connection",
			}
			h.renderTempl(w, r, proxy.Setup(data))
			return
		}
		if err := proxySvc.SetupConnection(ctx, baseURL, email, password, userID); err != nil {
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

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	conn, err := proxySvc.GetConnection(ctx)
	if err != nil || conn == nil {
		http.Redirect(w, r, "/proxy/setup", http.StatusSeeOther)
		return
	}

	if err := proxySvc.DeleteConnection(ctx, conn.ID); err != nil {
		slog.Error("Failed to delete NPM connection", "error", err)
	}

	http.Redirect(w, r, "/proxy/setup", http.StatusSeeOther)
}

// ProxySetupTestTempl handles POST /proxy/setup/test to test NPM connection.
func (h *Handler) ProxySetupTestTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Proxy Setup", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		data := proxy.SetupData{
			PageData: pageData,
			Error:    "Proxy service is not configured",
		}
		h.renderTempl(w, r, proxy.Setup(data))
		return
	}

	data := proxy.SetupData{
		PageData: pageData,
	}

	conn, err := proxySvc.GetConnection(ctx)
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
	if err := proxySvc.Sync(ctx); err != nil {
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

	proxySvc := h.services.Proxy()
	connected := false
	if proxySvc != nil {
		connected = proxySvc.IsConnected(r.Context())
	}

	data := proxy.NewData{
		PageData:  pageData,
		Connected: connected,
	}
	h.renderTempl(w, r, proxy.New(data))
}

// proxyHostForm captures the inputs of the proxy-host create /
// update form. forward_port is required > 0 — the underlying NPM
// service rejects 0 anyway, so the validator catches it earlier
// and keeps the operator out of an NPM error response.
type proxyHostForm struct {
	Domain                string `form:"domain" validate:"required"`
	ForwardScheme         string `form:"forward_scheme"`
	ForwardHost           string `form:"forward_host" validate:"required"`
	ForwardPort           int    `form:"forward_port" validate:"required,gt=0,lte=65535"`
	CertificateID         int    `form:"certificate_id" validate:"gte=0"`
	SSLEnabled            bool   `form:"ssl_enabled"`
	SSLForced             bool   `form:"ssl_forced"`
	HSTSEnabled           bool   `form:"hsts_enabled"`
	HSTSSubdomains        bool   `form:"hsts_subdomains"`
	HTTP2Support          bool   `form:"http2_support"`
	BlockExploits         bool   `form:"block_exploits"`
	CachingEnabled        bool   `form:"caching_enabled"`
	AllowWebsocketUpgrade bool   `form:"allow_websocket_upgrade"`
	AdvancedConfig        string `form:"advanced_config"`
}

// ProxyHostCreateTempl handles POST /proxy/hosts to create a new proxy host.
func (h *Handler) ProxyHostCreateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	var form proxyHostForm
	if msg := BindForm(r, &form); msg != "" {
		pageData := h.prepareTemplPageData(r, "New Proxy Host", "proxy")
		data := proxy.NewData{
			PageData:  pageData,
			Connected: proxySvc.IsConnected(ctx),
			Error:     msg,
		}
		h.renderTempl(w, r, proxy.New(data))
		return
	}

	forwardScheme := form.ForwardScheme
	if forwardScheme == "" {
		forwardScheme = "http"
	}

	host := &ProxyHostView{
		Domain:                form.Domain,
		ForwardScheme:         forwardScheme,
		ForwardHost:           form.ForwardHost,
		ForwardPort:           form.ForwardPort,
		CertificateID:         form.CertificateID,
		SSLEnabled:            form.SSLEnabled,
		SSLForced:             form.SSLForced,
		HSTSEnabled:           form.HSTSEnabled,
		HSTSSubdomains:        form.HSTSSubdomains,
		HTTP2Support:          form.HTTP2Support,
		BlockExploits:         form.BlockExploits,
		CachingEnabled:        form.CachingEnabled,
		AllowWebsocketUpgrade: form.AllowWebsocketUpgrade,
		AdvancedConfig:        form.AdvancedConfig,
		Enabled:               true,
	}

	if err := proxySvc.CreateHost(ctx, host); err != nil {
		slog.Error("Failed to create proxy host", "domain", form.Domain, "error", err)
		pageData := h.prepareTemplPageData(r, "New Proxy Host", "proxy")
		data := proxy.NewData{
			PageData:  pageData,
			Connected: proxySvc.IsConnected(ctx),
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

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	pageData := h.prepareTemplPageData(r, "Proxy Host", "proxy")
	connected := proxySvc.IsConnected(ctx)

	host, err := proxySvc.GetHost(ctx, id)
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
			SSLForced:     host.SSLForced,
			Enabled:       host.Enabled,
			ContainerName: host.Container,
			LastSync:      host.ModifiedOn,
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

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Proxy Host", "proxy")
	connected := proxySvc.IsConnected(ctx)

	host, err := proxySvc.GetHost(ctx, id)
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
			SSLForced:     host.SSLForced,
			Enabled:       host.Enabled,
			ContainerName: host.Container,
			LastSync:      host.ModifiedOn,
		},
	}
	h.renderTempl(w, r, proxy.Edit(data))
}

// ProxyHostUpdateTempl handles POST /proxy/hosts/{id} to update a proxy host.
// proxyHostUpdateForm extends proxyHostForm with the two
// Update-only fields: the `enabled` toggle (Create hardcodes it
// to true) and the `_method` form-trampoline that lets HTML
// forms emulate DELETE on the same endpoint.
type proxyHostUpdateForm struct {
	proxyHostForm
	Enabled bool   `form:"enabled"`
	Method  string `form:"_method"`
}

func (h *Handler) ProxyHostUpdateTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/proxy", http.StatusSeeOther)
		return
	}

	proxySvc := h.requireProxySvc(w, r)
	if proxySvc == nil {
		return
	}

	var form proxyHostUpdateForm
	if msg := BindForm(r, &form); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// Check for _method=DELETE override
	if form.Method == "DELETE" {
		h.proxyHostDeleteByID(w, r, id)
		return
	}

	forwardScheme := form.ForwardScheme
	if forwardScheme == "" {
		forwardScheme = "http"
	}

	host := &ProxyHostView{
		ID:                    id,
		Domain:                form.Domain,
		ForwardScheme:         forwardScheme,
		ForwardHost:           form.ForwardHost,
		ForwardPort:           form.ForwardPort,
		CertificateID:         form.CertificateID,
		SSLEnabled:            form.SSLEnabled,
		SSLForced:             form.SSLForced,
		HSTSEnabled:           form.HSTSEnabled,
		HSTSSubdomains:        form.HSTSSubdomains,
		HTTP2Support:          form.HTTP2Support,
		BlockExploits:         form.BlockExploits,
		CachingEnabled:        form.CachingEnabled,
		AllowWebsocketUpgrade: form.AllowWebsocketUpgrade,
		AdvancedConfig:        form.AdvancedConfig,
		Enabled:               form.Enabled,
	}

	if err := proxySvc.UpdateHost(ctx, host); err != nil {
		slog.Error("Failed to update proxy host", "id", id, "error", err)
		pageData := h.prepareTemplPageData(r, "Edit Proxy Host", "proxy")
		data := proxy.EditData{
			PageData:  pageData,
			Connected: proxySvc.IsConnected(ctx),
			Host: proxy.ProxyHost{
				ID:          idStr,
				DomainName:  form.Domain,
				ForwardHost: form.ForwardHost,
				ForwardPort: form.ForwardPort,
				SSLEnabled:  form.SSLEnabled,
				Enabled:     form.Enabled,
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

	proxySvc := h.services.Proxy()
	if proxySvc != nil {
		if err := proxySvc.RemoveHost(ctx, id); err != nil {
			slog.Error("Failed to delete proxy host", "id", id, "error", err)
		}
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

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if err := proxySvc.EnableHost(ctx, id); err != nil {
			slog.Error("Failed to enable proxy host", "id", id, "error", err)
		}
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

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if err := proxySvc.DisableHost(ctx, id); err != nil {
			slog.Error("Failed to disable proxy host", "id", id, "error", err)
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/proxy/%s", idStr), http.StatusSeeOther)
}

// ProxySyncTempl handles POST /proxy/sync to trigger NPM sync.
func (h *Handler) ProxySyncTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if err := proxySvc.Sync(ctx); err != nil {
			slog.Error("Failed to sync NPM", "error", err)
		}
	}

	http.Redirect(w, r, "/proxy", http.StatusSeeOther)
}
