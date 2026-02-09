// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/admin"
)

// LDAPConfigRepository defines the interface for LDAP config operations.
type LDAPConfigRepository interface {
	Create(ctx context.Context, input *postgres.CreateLDAPConfigInput) (*models.LDAPConfig, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPConfig, error)
	GetByName(ctx context.Context, name string) (*models.LDAPConfig, error)
	List(ctx context.Context) ([]*models.LDAPConfig, error)
	ListEnabled(ctx context.Context) ([]*models.LDAPConfig, error)
	Update(ctx context.Context, id uuid.UUID, input *postgres.UpdateLDAPConfigInput) (*models.LDAPConfig, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)
	CountEnabled(ctx context.Context) (int64, error)
}

// SetLDAPConfigRepo sets the LDAP config repository.
func (h *Handler) SetLDAPConfigRepo(repo LDAPConfigRepository) {
	h.ldapConfigRepo = repo
}

// LDAPProvidersTempl renders the LDAP providers list page.
func (h *Handler) LDAPProvidersTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "LDAP Providers", "settings")

	providers, err := h.ldapConfigRepo.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list LDAP providers", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to load LDAP providers")
		return
	}

	total, _ := h.ldapConfigRepo.Count(r.Context())
	enabled, _ := h.ldapConfigRepo.CountEnabled(r.Context())

	// Convert to template format
	providerItems := make([]admin.LDAPProviderItem, len(providers))
	for i, p := range providers {
		providerItems[i] = admin.LDAPProviderItem{
			ID:          p.ID.String(),
			Name:        p.Name,
			Host:        p.Host,
			Port:        p.Port,
			UseTLS:      p.UseTLS,
			StartTLS:    p.StartTLS,
			BaseDN:      p.BaseDN,
			DefaultRole: string(p.DefaultRole),
			IsEnabled:   p.IsEnabled,
			CreatedAt:   p.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt:   p.UpdatedAt.Format("2006-01-02 15:04"),
		}
	}

	data := admin.LDAPProvidersData{
		PageData:  ToTemplPageData(pageData),
		Providers: providerItems,
		Stats: admin.LDAPStats{
			Total:    total,
			Enabled:  enabled,
			Disabled: total - enabled,
		},
	}

	h.renderTempl(w, r, admin.LDAPProvidersList(data))
}

// LDAPProviderEditTempl renders the LDAP provider edit page.
func (h *Handler) LDAPProviderEditTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "Edit LDAP Provider", "settings")

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid provider ID")
		return
	}

	provider, err := h.ldapConfigRepo.GetByID(r.Context(), id)
	if err != nil {
		h.RenderError(w, r, http.StatusNotFound, "Error", "LDAP provider not found")
		return
	}

	data := admin.LDAPProviderEditData{
		PageData: ToTemplPageData(pageData),
		Provider: admin.LDAPProviderDetail{
			ID:            provider.ID.String(),
			Name:          provider.Name,
			Host:          provider.Host,
			Port:          provider.Port,
			UseTLS:        provider.UseTLS,
			StartTLS:      provider.StartTLS,
			SkipTLSVerify: provider.SkipTLSVerify,
			BindDN:        provider.BindDN,
			BaseDN:        provider.BaseDN,
			UserFilter:    provider.UserFilter,
			UsernameAttr:  provider.UsernameAttr,
			EmailAttr:     provider.EmailAttr,
			GroupFilter:   provider.GroupFilter,
			GroupAttr:     provider.GroupAttr,
			AdminGroup:    provider.AdminGroup,
			OperatorGroup: provider.OperatorGroup,
			DefaultRole:   string(provider.DefaultRole),
			IsEnabled:     provider.IsEnabled,
			CreatedAt:     provider.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:     provider.UpdatedAt.Format("2006-01-02 15:04:05"),
		},
	}

	h.renderTempl(w, r, admin.LDAPProviderEdit(data))
}

// LDAPProviderCreate handles creating a new LDAP provider.
func (h *Handler) LDAPProviderCreate(w http.ResponseWriter, r *http.Request) {
	// Enforce MaxLDAPServers license limit
	if h.licenseProvider != nil {
		info := h.licenseProvider.GetInfo()
		if info != nil {
			limit := info.Limits.MaxLDAPServers
			if limit > 0 {
				count, err := h.ldapConfigRepo.Count(r.Context())
				if err == nil && int(count) >= limit {
					h.redirect(w, r, fmt.Sprintf("/admin/ldap?error=LDAP+server+limit+reached+(%d/%d),+upgrade+your+license", count, limit))
					return
				}
			}
		}
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/ldap?error=Invalid+form+data")
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 389
	}

	// Encrypt bind password
	encryptedPassword, err := h.encryptor.Encrypt(r.FormValue("bind_password"))
	if err != nil {
		h.logger.Error("failed to encrypt bind password", "error", err)
		h.redirect(w, r, "/admin/ldap?error=Failed+to+encrypt+credentials")
		return
	}

	input := &postgres.CreateLDAPConfigInput{
		Name:          r.FormValue("name"),
		Host:          r.FormValue("host"),
		Port:          port,
		UseTLS:        r.FormValue("use_tls") == "on",
		StartTLS:      r.FormValue("start_tls") == "on",
		SkipTLSVerify: r.FormValue("skip_tls_verify") == "on",
		BindDN:        r.FormValue("bind_dn"),
		BindPassword:  encryptedPassword,
		BaseDN:        r.FormValue("base_dn"),
		UserFilter:    r.FormValue("user_filter"),
		UsernameAttr:  r.FormValue("username_attr"),
		EmailAttr:     r.FormValue("email_attr"),
		GroupFilter:   r.FormValue("group_filter"),
		GroupAttr:     r.FormValue("group_attr"),
		AdminGroup:    r.FormValue("admin_group"),
		OperatorGroup: r.FormValue("operator_group"),
		DefaultRole:   r.FormValue("default_role"),
		IsEnabled:     r.FormValue("is_enabled") == "on",
	}

	// Set defaults if not provided
	if input.DefaultRole == "" {
		input.DefaultRole = "viewer"
	}
	if input.UserFilter == "" {
		input.UserFilter = "(&(objectClass=person)(uid=%s))"
	}
	if input.UsernameAttr == "" {
		input.UsernameAttr = "uid"
	}
	if input.EmailAttr == "" {
		input.EmailAttr = "mail"
	}
	if input.GroupAttr == "" {
		input.GroupAttr = "memberOf"
	}

	_, err = h.ldapConfigRepo.Create(r.Context(), input)
	if err != nil {
		h.logger.Error("failed to create LDAP provider", "error", err)
		h.redirect(w, r, "/admin/ldap?error=Failed+to+create+provider")
		return
	}

	h.redirect(w, r, "/admin/ldap?success=Provider+created+successfully")
}

// LDAPProviderUpdate handles updating an LDAP provider.
func (h *Handler) LDAPProviderUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/ldap?error=Invalid+provider+ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/ldap/"+idStr+"?error=Invalid+form+data")
		return
	}

	name := r.FormValue("name")
	host := r.FormValue("host")
	port, _ := strconv.Atoi(r.FormValue("port"))
	useTLS := r.FormValue("use_tls") == "on"
	startTLS := r.FormValue("start_tls") == "on"
	skipTLSVerify := r.FormValue("skip_tls_verify") == "on"
	bindDN := r.FormValue("bind_dn")
	baseDN := r.FormValue("base_dn")
	userFilter := r.FormValue("user_filter")
	usernameAttr := r.FormValue("username_attr")
	emailAttr := r.FormValue("email_attr")
	groupFilter := r.FormValue("group_filter")
	groupAttr := r.FormValue("group_attr")
	adminGroup := r.FormValue("admin_group")
	operatorGroup := r.FormValue("operator_group")
	defaultRole := r.FormValue("default_role")
	isEnabled := r.FormValue("is_enabled") == "on"

	input := &postgres.UpdateLDAPConfigInput{
		Name:          &name,
		Host:          &host,
		Port:          &port,
		UseTLS:        &useTLS,
		StartTLS:      &startTLS,
		SkipTLSVerify: &skipTLSVerify,
		BindDN:        &bindDN,
		BaseDN:        &baseDN,
		UserFilter:    &userFilter,
		UsernameAttr:  &usernameAttr,
		EmailAttr:     &emailAttr,
		GroupFilter:   &groupFilter,
		GroupAttr:     &groupAttr,
		AdminGroup:    &adminGroup,
		OperatorGroup: &operatorGroup,
		DefaultRole:   &defaultRole,
		IsEnabled:     &isEnabled,
	}

	// Only update bind password if provided
	if bindPassword := r.FormValue("bind_password"); bindPassword != "" {
		encryptedPassword, err := h.encryptor.Encrypt(bindPassword)
		if err != nil {
			h.logger.Error("failed to encrypt bind password", "error", err)
			h.redirect(w, r, "/admin/ldap/"+idStr+"?error=Failed+to+encrypt+credentials")
			return
		}
		input.BindPassword = &encryptedPassword
	}

	_, err = h.ldapConfigRepo.Update(r.Context(), id, input)
	if err != nil {
		h.logger.Error("failed to update LDAP provider", "error", err)
		h.redirect(w, r, "/admin/ldap/"+idStr+"?error=Failed+to+update+provider")
		return
	}

	h.redirect(w, r, "/admin/ldap?success=Provider+updated+successfully")
}

// LDAPProviderDelete handles deleting an LDAP provider.
func (h *Handler) LDAPProviderDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/ldap?error=Invalid+provider+ID")
		return
	}

	if err := h.ldapConfigRepo.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete LDAP provider", "error", err)
		h.redirect(w, r, "/admin/ldap?error=Failed+to+delete+provider")
		return
	}

	h.redirect(w, r, "/admin/ldap?success=Provider+deleted+successfully")
}

// LDAPProviderEnable handles enabling an LDAP provider.
func (h *Handler) LDAPProviderEnable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/ldap?error=Invalid+provider+ID")
		return
	}

	enabled := true
	input := &postgres.UpdateLDAPConfigInput{
		IsEnabled: &enabled,
	}

	if _, err := h.ldapConfigRepo.Update(r.Context(), id, input); err != nil {
		h.logger.Error("failed to enable LDAP provider", "error", err)
		h.redirect(w, r, "/admin/ldap?error=Failed+to+enable+provider")
		return
	}

	h.redirect(w, r, "/admin/ldap?success=Provider+enabled")
}

// LDAPProviderDisable handles disabling an LDAP provider.
func (h *Handler) LDAPProviderDisable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/ldap?error=Invalid+provider+ID")
		return
	}

	enabled := false
	input := &postgres.UpdateLDAPConfigInput{
		IsEnabled: &enabled,
	}

	if _, err := h.ldapConfigRepo.Update(r.Context(), id, input); err != nil {
		h.logger.Error("failed to disable LDAP provider", "error", err)
		h.redirect(w, r, "/admin/ldap?error=Failed+to+disable+provider")
		return
	}

	h.redirect(w, r, "/admin/ldap?success=Provider+disabled")
}

// LDAPProviderTest handles testing an LDAP provider connection.
func (h *Handler) LDAPProviderTest(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Invalid provider ID","type":"error"}}`)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	provider, err := h.ldapConfigRepo.GetByID(r.Context(), id)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Provider not found","type":"error"}}`)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Decrypt bind password
	bindPassword, err := h.encryptor.Decrypt(provider.BindPassword)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to decrypt credentials","type":"error"}}`)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Test LDAP connection
	err = h.testLDAPConnection(provider.Host, provider.Port, provider.UseTLS, provider.StartTLS, provider.SkipTLSVerify, provider.BindDN, bindPassword)
	if err != nil {
		h.logger.Error("LDAP connection test failed", "provider", provider.Name, "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Connection failed: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Connection successful!","type":"success"}}`)
	w.WriteHeader(http.StatusOK)
}

// testLDAPConnection tests an LDAP connection with the given parameters.
func (h *Handler) testLDAPConnection(host string, port int, useTLS, startTLS, skipTLSVerify bool, bindDN, bindPassword string) error {
	var l *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", host, port)

	// Set connection timeout
	ldap.DefaultTimeout = 10 * time.Second

	// TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipTLSVerify,
		ServerName:         host,
	}

	if useTLS {
		// LDAPS (TLS from start)
		l, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", address), ldap.DialWithTLSConfig(tlsConfig))
	} else {
		// Plain LDAP
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s", address))
		if err == nil && startTLS {
			// Upgrade to TLS via StartTLS
			err = l.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer l.Close()

	// Attempt to bind
	if bindDN != "" {
		if err := l.Bind(bindDN, bindPassword); err != nil {
			return fmt.Errorf("bind failed: %w", err)
		}
	} else {
		// Anonymous bind
		if err := l.UnauthenticatedBind(""); err != nil {
			return fmt.Errorf("anonymous bind failed: %w", err)
		}
	}

	return nil
}

// escapeJSON escapes a string for safe inclusion in JSON
func escapeJSON(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '"':
			result += "\\\""
		case '\\':
			result += "\\\\"
		case '\n':
			result += "\\n"
		case '\r':
			result += "\\r"
		case '\t':
			result += "\\t"
		default:
			result += string(c)
		}
	}
	return result
}
