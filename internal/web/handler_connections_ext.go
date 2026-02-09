// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/connections"
)

// ============================================================================
// Database Service Interface
// ============================================================================

// DatabaseService interface for managing database connections.
type DatabaseService interface {
	CreateConnection(ctx context.Context, input models.CreateDatabaseConnectionInput, userID uuid.UUID) (*models.DatabaseConnection, error)
	GetConnection(ctx context.Context, id uuid.UUID) (*models.DatabaseConnection, error)
	ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.DatabaseConnection, error)
	UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateDatabaseConnectionInput) error
	DeleteConnection(ctx context.Context, id uuid.UUID) error
	TestConnection(ctx context.Context, id uuid.UUID) (models.DatabaseTestResulter, error)
	ListTables(ctx context.Context, id uuid.UUID) ([]models.DatabaseTable, error)
	GetTableColumns(ctx context.Context, id uuid.UUID, tableName string) ([]models.DatabaseColumn, error)
	GetTableData(ctx context.Context, id uuid.UUID, tableName string, page, pageSize int) ([]map[string]interface{}, int64, error)
	ExecuteQuery(ctx context.Context, id uuid.UUID, query string, writeMode bool) (*models.DatabaseQueryResult, error)
}

// SetDatabaseService sets the database service.
func (h *Handler) SetDatabaseService(svc DatabaseService) {
	h.databaseService = svc
}

// ============================================================================
// LDAP Browser Service Interface
// ============================================================================

// LDAPBrowserService interface for managing LDAP connections.
type LDAPBrowserService interface {
	CreateConnection(ctx context.Context, input models.CreateLDAPConnectionInput, userID uuid.UUID) (*models.LDAPConnection, error)
	GetConnection(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error)
	ListConnections(ctx context.Context, userID uuid.UUID) ([]*models.LDAPConnection, error)
	UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateLDAPConnectionInput) error
	DeleteConnection(ctx context.Context, id uuid.UUID) error
	TestConnection(ctx context.Context, id uuid.UUID) (models.LDAPTestResulter, error)
	ListEntries(ctx context.Context, id uuid.UUID, baseDN string, scope int) ([]models.LDAPEntry, error)
	GetEntry(ctx context.Context, id uuid.UUID, dn string) (*models.LDAPEntry, error)
	Search(ctx context.Context, id uuid.UUID, baseDN, filter string, scope int, attributes []string) (*models.LDAPSearchResult, error)
}

// SetLDAPBrowserService sets the LDAP browser service.
func (h *Handler) SetLDAPBrowserService(svc LDAPBrowserService) {
	h.ldapBrowserService = svc
}

// ============================================================================
// SSH Tunnels Handlers
// ============================================================================

// SSHTunnelsTempl renders the SSH tunnels page.
func (h *Handler) SSHTunnelsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	pageData := h.prepareTemplPageData(r, "SSH Tunnels", "connections")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid connection ID")
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable", "SSH service not available")
		return
	}

	conn, err := svc.GetConnection(ctx, connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Connection Not Found", "SSH connection not found")
		return
	}

	// Get tunnels from service
	var tunnels []connections.SSHTunnelData
	tunnelList, err := svc.ListTunnelsByConnection(ctx, connID)
	if err == nil && tunnelList != nil {
		for _, t := range tunnelList {
			tunnels = append(tunnels, connections.SSHTunnelData{
				ID:         t.ID.String(),
				LocalHost:  t.LocalHost,
				LocalPort:  t.LocalPort,
				RemoteHost: t.RemoteHost,
				RemotePort: t.RemotePort,
				Status:     string(t.Status),
				Type:       string(t.Type),
			})
		}
	}

	data := connections.SSHTunnelsPageData{
		PageData: pageData,
		Connection: connections.SSHConnectionData{
			ID:       conn.ID.String(),
			Name:     conn.Name,
			Host:     conn.Host,
			Port:     conn.Port,
			Username: conn.Username,
		},
		Tunnels: tunnels,
	}

	h.renderTempl(w, r, connections.SSHTunnels(data))
}

// SSHTunnelCreate creates a new SSH tunnel.
func (h *Handler) SSHTunnelCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	// Get current user
	user := GetUserFromContext(ctx)
	if user == nil {
		h.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		h.jsonError(w, "invalid user session", http.StatusBadRequest)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.jsonError(w, "invalid form data", http.StatusBadRequest)
		return
	}

	tunnelType := r.FormValue("type")
	localHost := r.FormValue("local_host")
	if localHost == "" {
		localHost = "127.0.0.1"
	}

	localPort := 0
	if lp := r.FormValue("local_port"); lp != "" {
		if _, err := fmt.Sscanf(lp, "%d", &localPort); err != nil || localPort < 1 || localPort > 65535 {
			h.jsonError(w, "invalid local port", http.StatusBadRequest)
			return
		}
	}

	remoteHost := r.FormValue("remote_host")
	if remoteHost == "" {
		remoteHost = "localhost"
	}

	remotePort := 0
	if rp := r.FormValue("remote_port"); rp != "" {
		fmt.Sscanf(rp, "%d", &remotePort)
	}

	// Create tunnel
	input := models.CreateSSHTunnelInput{
		ConnectionID: connID,
		Type:         models.SSHTunnelType(tunnelType),
		LocalHost:    localHost,
		LocalPort:    localPort,
		RemoteHost:   remoteHost,
		RemotePort:   remotePort,
	}

	tunnel, err := svc.CreateTunnel(ctx, input, userID)
	if err != nil {
		h.jsonError(w, "failed to create tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"id":      tunnel.ID.String(),
		"message": "Tunnel created successfully",
	})
}

// SSHTunnelToggle toggles an SSH tunnel on/off.
func (h *Handler) SSHTunnelToggle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tunnelIDStr := chi.URLParam(r, "tunnelID")

	tunnelID, err := uuid.Parse(tunnelIDStr)
	if err != nil {
		h.jsonError(w, "invalid tunnel ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if err := svc.ToggleTunnel(ctx, tunnelID); err != nil {
		h.jsonError(w, "failed to toggle tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message": "Tunnel toggled",
	})
}

// SSHTunnelDelete deletes an SSH tunnel.
func (h *Handler) SSHTunnelDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tunnelIDStr := chi.URLParam(r, "tunnelID")

	tunnelID, err := uuid.Parse(tunnelIDStr)
	if err != nil {
		h.jsonError(w, "invalid tunnel ID", http.StatusBadRequest)
		return
	}

	svc := h.getSSHService()
	if svc == nil {
		h.jsonError(w, "SSH service not available", http.StatusServiceUnavailable)
		return
	}

	if err := svc.DeleteTunnel(ctx, tunnelID); err != nil {
		h.jsonError(w, "failed to delete tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonSuccess(w, map[string]interface{}{
		"message": "Tunnel deleted",
	})
}

// ============================================================================
// Database Connection Handlers
// ============================================================================

// DatabaseConnectionsTempl renders the database connections list page.
func (h *Handler) DatabaseConnectionsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Database Connections", "connections-database")
	userData := h.getUserData(r)

	var connData []connections.DatabaseConnectionData

	if h.databaseService != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			conns, err := h.databaseService.ListConnections(ctx, userID)
			if err == nil {
				for _, conn := range conns {
					connData = append(connData, toDatabaseConnectionData(conn))
				}
			}
		}
	}

	data := connections.DatabaseConnectionsListData{
		PageData:    pageData,
		Connections: connData,
	}

	h.renderTempl(w, r, connections.DatabaseConnectionsList(data))
}

// DatabaseConnectionCreate creates a new database connection.
func (h *Handler) DatabaseConnectionCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userData := h.getUserData(r)

	if h.databaseService == nil {
		http.Error(w, "Database service not available", http.StatusServiceUnavailable)
		return
	}

	if userData == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userData.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = models.GetDefaultPort(models.DatabaseType(r.FormValue("type")))
	}

	input := models.CreateDatabaseConnectionInput{
		Name:     r.FormValue("name"),
		Type:     models.DatabaseType(r.FormValue("type")),
		Host:     r.FormValue("host"),
		Port:     port,
		Database: r.FormValue("database"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		SSL:      r.FormValue("ssl") == "on" || r.FormValue("ssl") == "true",
	}

	_, err = h.databaseService.CreateConnection(ctx, input, userID)
	if err != nil {
		http.Error(w, "Failed to create connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/connections/database", http.StatusSeeOther)
}

// DatabaseBrowserTempl renders the database browser page.
func (h *Handler) DatabaseBrowserTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	pageData := h.prepareTemplPageData(r, "Database Browser", "connections-database")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid connection ID")
		return
	}

	if h.databaseService == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable", "Database service not available")
		return
	}

	conn, err := h.databaseService.GetConnection(ctx, connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Connection Not Found", "Database connection not found")
		return
	}

	// Get tables
	var tables []connections.DatabaseTableData
	tableList, err := h.databaseService.ListTables(ctx, connID)
	if err == nil {
		for _, t := range tableList {
			tables = append(tables, connections.DatabaseTableData{
				Name:     t.Name,
				Type:     t.Type,
				RowCount: t.RowCount,
				Size:     t.SizeHuman,
				Schema:   t.Schema,
			})
		}
	}

	currentTable := r.URL.Query().Get("table")
	var columns []connections.DatabaseColumnData
	var rows []map[string]interface{}
	var rowCount int64
	page := 1
	pageSize := 50
	totalPages := 1

	if currentTable != "" {
		// Get columns
		colList, err := h.databaseService.GetTableColumns(ctx, connID, currentTable)
		if err == nil {
			for _, c := range colList {
				columns = append(columns, connections.DatabaseColumnData{
					Name:       c.Name,
					Type:       c.Type,
					Nullable:   c.Nullable,
					Default:    c.Default,
					PrimaryKey: c.IsPrimaryKey,
					ForeignKey: c.ForeignKey,
				})
			}
		}

		// Get data
		if pageStr := r.URL.Query().Get("page"); pageStr != "" {
			page, _ = strconv.Atoi(pageStr)
			if page < 1 {
				page = 1
			}
		}

		rows, rowCount, err = h.databaseService.GetTableData(ctx, connID, currentTable, page, pageSize)
		if err == nil {
			totalPages = int((rowCount + int64(pageSize) - 1) / int64(pageSize))
			if totalPages < 1 {
				totalPages = 1
			}
		}
	}

	data := connections.DatabaseBrowserData{
		PageData:     pageData,
		Connection:   toDatabaseConnectionData(conn),
		Tables:       tables,
		CurrentTable: currentTable,
		Columns:      columns,
		Rows:         rows,
		RowCount:     rowCount,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
		WriteEnabled: false, // Read-only by default
	}

	h.renderTempl(w, r, connections.DatabaseBrowser(data))
}

// DatabaseConnectionTest tests a database connection.
func (h *Handler) DatabaseConnectionTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.databaseService == nil {
		h.jsonError(w, "Database service not available", http.StatusServiceUnavailable)
		return
	}

	result, err := h.databaseService.TestConnection(ctx, connID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    result.IsSuccess(),
		"message":    result.GetMessage(),
		"latency_ms": result.GetLatency().Milliseconds(),
	})
}

// DatabaseConnectionDelete deletes a database connection.
func (h *Handler) DatabaseConnectionDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.databaseService == nil {
		h.jsonError(w, "Database service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.databaseService.DeleteConnection(ctx, connID); err != nil {
		h.jsonError(w, "failed to delete connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DatabaseWriteModeToggle toggles write mode for database browser.
func (h *Handler) DatabaseWriteModeToggle(w http.ResponseWriter, r *http.Request) {
	// Write mode stored in session/cookie - for now just acknowledge
	w.WriteHeader(http.StatusOK)
}

// DatabaseQueryTempl renders the database query page.
func (h *Handler) DatabaseQueryTempl(w http.ResponseWriter, r *http.Request) {
	h.DatabaseBrowserTempl(w, r)
}

// DatabaseQueryExecute executes a database query.
func (h *Handler) DatabaseQueryExecute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.databaseService == nil {
		h.jsonError(w, "Database service not available", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Query     string `json:"query"`
		WriteMode bool   `json:"write_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.databaseService.ExecuteQuery(ctx, connID, req.Query, req.WriteMode)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       result.Error == "",
		"error":         result.Error,
		"columns":       result.Columns,
		"rows":          result.Rows,
		"row_count":     result.RowCount,
		"affected_rows": result.AffectedRows,
		"duration_ms":   result.Duration.Milliseconds(),
	})
}

// Helper function to convert model to template data
func toDatabaseConnectionData(conn *models.DatabaseConnection) connections.DatabaseConnectionData {
	data := connections.DatabaseConnectionData{
		ID:       conn.ID.String(),
		Name:     conn.Name,
		Type:     connections.DatabaseType(conn.Type),
		Host:     conn.Host,
		Port:     conn.Port,
		Database: conn.Database,
		Username: conn.Username,
		SSL:      conn.SSL,
		Status:   string(conn.Status),
	}

	if conn.LastChecked != nil {
		data.LastChecked = formatTimeAgo(*conn.LastChecked)
	}

	return data
}

func formatTimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return strconv.Itoa(m) + " minutes ago"
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return strconv.Itoa(h) + " hours ago"
	default:
		return t.Format("Jan 2, 2006")
	}
}

// ============================================================================
// LDAP Connection Handlers
// ============================================================================

// LDAPConnectionsTempl renders the LDAP connections list page.
func (h *Handler) LDAPConnectionsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "LDAP Connections", "connections-ldap")
	userData := h.getUserData(r)

	var connData []connections.LDAPConnectionData

	if h.ldapBrowserService != nil && userData != nil {
		userID, err := uuid.Parse(userData.ID)
		if err == nil {
			conns, err := h.ldapBrowserService.ListConnections(ctx, userID)
			if err == nil {
				for _, conn := range conns {
					connData = append(connData, toLDAPConnectionData(conn))
				}
			}
		}
	}

	data := connections.LDAPConnectionsListData{
		PageData:    pageData,
		Connections: connData,
	}

	h.renderTempl(w, r, connections.LDAPConnectionsList(data))
}

// LDAPConnectionCreate creates a new LDAP connection.
func (h *Handler) LDAPConnectionCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userData := h.getUserData(r)

	if h.ldapBrowserService == nil {
		http.Error(w, "LDAP service not available", http.StatusServiceUnavailable)
		return
	}

	if userData == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID, err := uuid.Parse(userData.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 389
	}

	input := models.CreateLDAPConnectionInput{
		Name:          r.FormValue("name"),
		Host:          r.FormValue("host"),
		Port:          port,
		UseTLS:        r.FormValue("use_tls") == "on" || r.FormValue("use_tls") == "true",
		StartTLS:      r.FormValue("start_tls") == "on" || r.FormValue("start_tls") == "true",
		SkipTLSVerify: r.FormValue("skip_tls_verify") == "on" || r.FormValue("skip_tls_verify") == "true",
		BindDN:        r.FormValue("bind_dn"),
		BindPassword:  r.FormValue("bind_password"),
		BaseDN:        r.FormValue("base_dn"),
	}

	_, err = h.ldapBrowserService.CreateConnection(ctx, input, userID)
	if err != nil {
		http.Error(w, "Failed to create connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/connections/ldap", http.StatusSeeOther)
}

// LDAPBrowserTempl renders the LDAP browser page.
func (h *Handler) LDAPBrowserTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	pageData := h.prepareTemplPageData(r, "LDAP Browser", "connections-ldap")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid connection ID")
		return
	}

	if h.ldapBrowserService == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable", "LDAP service not available")
		return
	}

	conn, err := h.ldapBrowserService.GetConnection(ctx, connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Connection Not Found", "LDAP connection not found")
		return
	}

	// Get entries at base DN or current DN
	currentDN := r.URL.Query().Get("entry")
	if currentDN == "" {
		currentDN = conn.BaseDN
	}

	var entries []connections.LDAPEntryData
	entryList, err := h.ldapBrowserService.ListEntries(ctx, connID, currentDN, 1) // ScopeSingleLevel
	if err == nil {
		for _, e := range entryList {
			entries = append(entries, connections.LDAPEntryData{
				DN:          e.DN,
				ObjectClass: e.ObjectClass,
				HasChildren: e.HasChildren,
			})
		}
	}

	// Get current entry details if specified
	var currentEntry *connections.LDAPEntryData
	var attributes []connections.LDAPAttributeData
	if entryDN := r.URL.Query().Get("entry"); entryDN != "" {
		entry, err := h.ldapBrowserService.GetEntry(ctx, connID, entryDN)
		if err == nil {
			currentEntry = &connections.LDAPEntryData{
				DN:          entry.DN,
				ObjectClass: entry.ObjectClass,
				HasChildren: entry.HasChildren,
			}
			for attrName, attrValues := range entry.Attributes {
				attributes = append(attributes, connections.LDAPAttributeData{
					Name:   attrName,
					Values: attrValues,
				})
			}
		}
	}

	data := connections.LDAPBrowserData{
		PageData:     pageData,
		Connection:   toLDAPConnectionData(conn),
		BaseDN:       conn.BaseDN,
		CurrentDN:    currentDN,
		Entries:      entries,
		CurrentEntry: currentEntry,
		Attributes:   attributes,
		WriteEnabled: false,
	}

	h.renderTempl(w, r, connections.LDAPBrowser(data))
}

// LDAPConnectionTest tests an LDAP connection.
func (h *Handler) LDAPConnectionTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.ldapBrowserService == nil {
		h.jsonError(w, "LDAP service not available", http.StatusServiceUnavailable)
		return
	}

	result, err := h.ldapBrowserService.TestConnection(ctx, connID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    result.IsSuccess(),
		"message":    result.GetMessage(),
		"latency_ms": result.GetLatency().Milliseconds(),
	})
}

// LDAPConnectionDelete deletes an LDAP connection.
func (h *Handler) LDAPConnectionDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.ldapBrowserService == nil {
		h.jsonError(w, "LDAP service not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.ldapBrowserService.DeleteConnection(ctx, connID); err != nil {
		h.jsonError(w, "failed to delete connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// LDAPWriteModeToggle toggles write mode for LDAP browser.
func (h *Handler) LDAPWriteModeToggle(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// LDAPSearchTempl renders the LDAP search page.
func (h *Handler) LDAPSearchTempl(w http.ResponseWriter, r *http.Request) {
	h.LDAPBrowserTempl(w, r)
}

// LDAPSearchExecute executes an LDAP search.
func (h *Handler) LDAPSearchExecute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.jsonError(w, "invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.ldapBrowserService == nil {
		h.jsonError(w, "LDAP service not available", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		BaseDN     string   `json:"base_dn"`
		Filter     string   `json:"filter"`
		Scope      int      `json:"scope"`
		Attributes []string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.ldapBrowserService.Search(ctx, connID, req.BaseDN, req.Filter, req.Scope, req.Attributes)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"entries":     result.Entries,
		"total_count": result.TotalCount,
		"search_time": result.SearchTime.Milliseconds(),
	})
}

// ============================================================================
// RDP Connection Handlers
// ============================================================================

// RDPConnectionsTempl renders the RDP connections list page.
func (h *Handler) RDPConnectionsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "RDP Connections", "connections-rdp")

	data := connections.RDPConnectionsListData{
		PageData:    pageData,
		Connections: nil, // RDP service not yet implemented
	}

	h.renderTempl(w, r, connections.RDPConnectionsList(data))
}

// RDPConnectionNewTempl renders the new RDP connection form.
func (h *Handler) RDPConnectionNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New RDP Connection", "connections-rdp")

	data := connections.RDPConnectionNewData{
		PageData: pageData,
	}

	h.renderTempl(w, r, connections.RDPConnectionNew(data))
}

// RDPConnectionCreate creates a new RDP connection.
func (h *Handler) RDPConnectionCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// TODO: Implement RDP service backend to persist connections
	http.Redirect(w, r, "/connections/rdp", http.StatusSeeOther)
}

// RDPConnectionDetailTempl renders the RDP connection detail page.
func (h *Handler) RDPConnectionDetailTempl(w http.ResponseWriter, r *http.Request) {
	connID := chi.URLParam(r, "id")
	pageData := h.prepareTemplPageData(r, "RDP Connection", "connections-rdp")

	// Placeholder: return a stub connection for now
	shortID := connID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	data := connections.RDPConnectionDetailData{
		PageData: pageData,
		Connection: connections.RDPConnectionData{
			ID:         connID,
			Name:       "Connection " + shortID,
			Host:       "unknown",
			Port:       3389,
			Status:     "unknown",
			Resolution: "1920x1080",
			ColorDepth: "32",
			Security:   "any",
		},
	}

	h.renderTempl(w, r, connections.RDPConnectionDetail(data))
}

// RDPConnectionUpdate updates an RDP connection.
func (h *Handler) RDPConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	connID := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// TODO: Implement RDP service backend to update connections
	http.Redirect(w, r, "/connections/rdp/"+connID, http.StatusSeeOther)
}

// RDPConnectionDelete deletes an RDP connection.
func (h *Handler) RDPConnectionDelete(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement RDP service backend to delete connections
	w.WriteHeader(http.StatusOK)
}

// RDPConnectionTest tests an RDP connection (TCP connectivity check).
func (h *Handler) RDPConnectionTest(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement TCP dial test to RDP port
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": "RDP service not yet implemented",
	})
}

// LDAPConnectionSettingsTempl renders the LDAP connection settings/edit page.
func (h *Handler) LDAPConnectionSettingsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")
	pageData := h.prepareTemplPageData(r, "LDAP Settings", "connections-ldap")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid connection ID")
		return
	}

	if h.ldapBrowserService == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Service Unavailable", "LDAP service not available")
		return
	}

	conn, err := h.ldapBrowserService.GetConnection(ctx, connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Connection Not Found", "LDAP connection not found")
		return
	}

	data := connections.LDAPConnectionSettingsData{
		PageData:   pageData,
		Connection: toLDAPConnectionData(conn),
	}

	h.renderTempl(w, r, connections.LDAPConnectionSettings(data))
}

// LDAPConnectionSettingsUpdate updates an LDAP connection from the settings form.
func (h *Handler) LDAPConnectionSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connIDStr := chi.URLParam(r, "id")

	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		http.Error(w, "Invalid connection ID", http.StatusBadRequest)
		return
	}

	if h.ldapBrowserService == nil {
		http.Error(w, "LDAP service not available", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 389
	}

	input := models.UpdateLDAPConnectionInput{
		Name:          strPtr(r.FormValue("name")),
		Host:          strPtr(r.FormValue("host")),
		Port:          &port,
		BaseDN:        strPtr(r.FormValue("base_dn")),
		BindDN:        strPtr(r.FormValue("bind_dn")),
		UseTLS:        boolPtr(r.FormValue("use_tls") == "on"),
		StartTLS:      boolPtr(r.FormValue("start_tls") == "on"),
		SkipTLSVerify: boolPtr(r.FormValue("skip_tls_verify") == "on"),
	}

	if pw := r.FormValue("bind_password"); pw != "" {
		input.BindPassword = strPtr(pw)
	}

	if err := h.ldapBrowserService.UpdateConnection(ctx, connID, input); err != nil {
		http.Error(w, "Failed to update connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/connections/ldap/"+connIDStr+"/settings", http.StatusSeeOther)
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// Helper function to convert model to template data
func toLDAPConnectionData(conn *models.LDAPConnection) connections.LDAPConnectionData {
	data := connections.LDAPConnectionData{
		ID:     conn.ID.String(),
		Name:   conn.Name,
		Host:   conn.Host,
		Port:   conn.Port,
		BaseDN: conn.BaseDN,
		BindDN: conn.BindDN,
		UseSSL: conn.UseTLS,
		UseTLS: conn.StartTLS,
		Status: string(conn.Status),
	}

	if conn.LastChecked != nil {
		data.LastChecked = formatTimeAgo(*conn.LastChecked)
	}

	return data
}
