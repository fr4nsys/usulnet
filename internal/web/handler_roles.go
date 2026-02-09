// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/admin"
)

// RoleRepository defines the interface for role operations.
type RoleRepository interface {
	Create(ctx context.Context, role *models.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetByName(ctx context.Context, name string) (*models.Role, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, opts postgres.RoleListOptions) ([]*models.Role, int, error)
	GetAll(ctx context.Context) ([]*models.Role, error)
	GetSystemRoles(ctx context.Context) ([]*models.Role, error)
	CountUsersWithRole(ctx context.Context, roleID uuid.UUID) (int, error)
	CountCustomRoles(ctx context.Context) (int, error)
}

// SetRoleRepo sets the role repository.
func (h *Handler) SetRoleRepo(repo RoleRepository) {
	h.roleRepo = repo
}

// RolesTempl renders the roles list page.
func (h *Handler) RolesTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "Roles & Permissions", "roles")

	roles, total, err := h.roleRepo.List(r.Context(), postgres.RoleListOptions{
		IncludeInactive: true,
		IncludeSystem:   true,
		Limit:           100,
	})
	if err != nil {
		h.logger.Error("failed to list roles", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to load roles")
		return
	}

	// Convert to template format and count users
	roleItems := make([]admin.RoleItem, len(roles))
	var systemCount, customCount, activeCount, inactiveCount int

	for i, role := range roles {
		userCount, _ := h.roleRepo.CountUsersWithRole(r.Context(), role.ID)

		roleItems[i] = admin.RoleItem{
			ID:          role.ID.String(),
			Name:        role.Name,
			DisplayName: role.DisplayName,
			Description: ptrToString(role.Description),
			Permissions: role.Permissions,
			IsSystem:    role.IsSystem,
			IsActive:    role.IsActive,
			Priority:    role.Priority,
			UserCount:   userCount,
			CreatedAt:   role.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt:   role.UpdatedAt.Format("2006-01-02 15:04"),
		}

		if role.IsSystem {
			systemCount++
		} else {
			customCount++
		}
		if role.IsActive {
			activeCount++
		} else {
			inactiveCount++
		}
	}

	data := admin.RolesData{
		PageData: ToTemplPageData(pageData),
		Roles:    roleItems,
		Stats: admin.RoleStats{
			Total:    total,
			System:   systemCount,
			Custom:   customCount,
			Active:   activeCount,
			Inactive: inactiveCount,
		},
	}

	h.renderTempl(w, r, admin.RolesList(data))
}

// RoleEditTempl renders the role edit page.
func (h *Handler) RoleEditTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.preparePageData(r, "Edit Role", "roles")

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid role ID")
		return
	}

	role, err := h.roleRepo.GetByID(r.Context(), id)
	if err != nil {
		h.RenderError(w, r, http.StatusNotFound, "Error", "Role not found")
		return
	}

	// Build permissions with checked state
	allPerms := buildPermissionCategories(role.Permissions)

	data := admin.RoleEditData{
		PageData: ToTemplPageData(pageData),
		Role: admin.RoleItem{
			ID:          role.ID.String(),
			Name:        role.Name,
			DisplayName: role.DisplayName,
			Description: ptrToString(role.Description),
			Permissions: role.Permissions,
			IsSystem:    role.IsSystem,
			IsActive:    role.IsActive,
			Priority:    role.Priority,
			CreatedAt:   role.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:   role.UpdatedAt.Format("2006-01-02 15:04:05"),
		},
		AllPerms: allPerms,
	}

	h.renderTempl(w, r, admin.RoleEdit(data))
}

// RoleCreate handles creating a new role.
func (h *Handler) RoleCreate(w http.ResponseWriter, r *http.Request) {
	// Enforce MaxCustomRoles license limit
	if h.licenseProvider != nil {
		info := h.licenseProvider.GetInfo()
		if info != nil {
			limit := info.Limits.MaxCustomRoles
			if limit > 0 {
				count, err := h.roleRepo.CountCustomRoles(r.Context())
				if err == nil && count >= limit {
					h.redirect(w, r, fmt.Sprintf("/admin/roles?error=Custom+role+limit+reached+(%d/%d),+upgrade+your+license", count, limit))
					return
				}
			}
		}
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/roles?error=Invalid+form+data")
		return
	}

	name := r.FormValue("name")
	displayName := r.FormValue("display_name")
	description := r.FormValue("description")
	priorityStr := r.FormValue("priority")
	isActive := r.FormValue("is_active") == "on"
	permissions := r.Form["permissions"]

	priority, _ := strconv.Atoi(priorityStr)
	if priority < 1 || priority > 99 {
		priority = 25
	}

	if len(permissions) == 0 {
		h.redirect(w, r, "/admin/roles?error=At+least+one+permission+required")
		return
	}

	role := &models.Role{
		Name:        name,
		DisplayName: displayName,
		Description: stringToPtr(description),
		Permissions: permissions,
		IsSystem:    false,
		IsActive:    isActive,
		Priority:    priority,
	}

	if err := h.roleRepo.Create(r.Context(), role); err != nil {
		h.logger.Error("failed to create role", "error", err)
		h.redirect(w, r, "/admin/roles?error=Failed+to+create+role")
		return
	}

	h.redirect(w, r, "/admin/roles?success=Role+created+successfully")
}

// RoleUpdate handles updating a role.
func (h *Handler) RoleUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Invalid+role+ID")
		return
	}

	role, err := h.roleRepo.GetByID(r.Context(), id)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Role+not+found")
		return
	}

	// Cannot modify system roles
	if role.IsSystem {
		h.redirect(w, r, "/admin/roles?error=Cannot+modify+system+roles")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/admin/roles/"+idStr+"?error=Invalid+form+data")
		return
	}

	displayName := r.FormValue("display_name")
	description := r.FormValue("description")
	priorityStr := r.FormValue("priority")
	isActive := r.FormValue("is_active") == "on"
	permissions := r.Form["permissions"]

	priority, _ := strconv.Atoi(priorityStr)
	if priority < 1 || priority > 99 {
		priority = role.Priority
	}

	if len(permissions) == 0 {
		h.redirect(w, r, "/admin/roles/"+idStr+"?error=At+least+one+permission+required")
		return
	}

	// Update role fields
	role.DisplayName = displayName
	role.Description = stringToPtr(description)
	role.Priority = priority
	role.IsActive = isActive
	role.Permissions = permissions

	if err := h.roleRepo.Update(r.Context(), role); err != nil {
		h.logger.Error("failed to update role", "error", err)
		h.redirect(w, r, "/admin/roles/"+idStr+"?error=Failed+to+update+role")
		return
	}

	h.redirect(w, r, "/admin/roles?success=Role+updated+successfully")
}

// RoleDelete handles deleting a role.
func (h *Handler) RoleDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Invalid+role+ID")
		return
	}

	if err := h.roleRepo.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete role", "error", err)
		h.redirect(w, r, "/admin/roles?error=Failed+to+delete+role")
		return
	}

	h.redirect(w, r, "/admin/roles?success=Role+deleted+successfully")
}

// RoleEnable handles enabling a role.
func (h *Handler) RoleEnable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Invalid+role+ID")
		return
	}

	role, err := h.roleRepo.GetByID(r.Context(), id)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Role+not+found")
		return
	}

	if role.IsSystem {
		h.redirect(w, r, "/admin/roles?error=Cannot+modify+system+roles")
		return
	}

	role.IsActive = true
	if err := h.roleRepo.Update(r.Context(), role); err != nil {
		h.logger.Error("failed to enable role", "error", err)
		h.redirect(w, r, "/admin/roles?error=Failed+to+enable+role")
		return
	}

	h.redirect(w, r, "/admin/roles?success=Role+enabled")
}

// RoleDisable handles disabling a role.
func (h *Handler) RoleDisable(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Invalid+role+ID")
		return
	}

	role, err := h.roleRepo.GetByID(r.Context(), id)
	if err != nil {
		h.redirect(w, r, "/admin/roles?error=Role+not+found")
		return
	}

	if role.IsSystem {
		h.redirect(w, r, "/admin/roles?error=Cannot+modify+system+roles")
		return
	}

	role.IsActive = false
	if err := h.roleRepo.Update(r.Context(), role); err != nil {
		h.logger.Error("failed to disable role", "error", err)
		h.redirect(w, r, "/admin/roles?error=Failed+to+disable+role")
		return
	}

	h.redirect(w, r, "/admin/roles?success=Role+disabled")
}

// Helper functions

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func buildPermissionCategories(selectedPerms []string) []admin.PermissionCategoryData {
	// Build a set of selected permissions
	selected := make(map[string]bool)
	for _, p := range selectedPerms {
		selected[p] = true
	}

	categories := []admin.PermissionCategoryData{
		{
			Name:     "Containers",
			Category: "container",
			Permissions: []admin.PermissionData{
				{Name: "container:view", DisplayName: "View containers", Checked: selected["container:view"]},
				{Name: "container:create", DisplayName: "Create containers", Checked: selected["container:create"]},
				{Name: "container:start", DisplayName: "Start containers", Checked: selected["container:start"]},
				{Name: "container:stop", DisplayName: "Stop containers", Checked: selected["container:stop"]},
				{Name: "container:restart", DisplayName: "Restart containers", Checked: selected["container:restart"]},
				{Name: "container:remove", DisplayName: "Remove containers", Checked: selected["container:remove"]},
				{Name: "container:exec", DisplayName: "Execute commands", Checked: selected["container:exec"]},
				{Name: "container:logs", DisplayName: "View logs", Checked: selected["container:logs"]},
			},
		},
		{
			Name:     "Images",
			Category: "image",
			Permissions: []admin.PermissionData{
				{Name: "image:view", DisplayName: "View images", Checked: selected["image:view"]},
				{Name: "image:pull", DisplayName: "Pull images", Checked: selected["image:pull"]},
				{Name: "image:remove", DisplayName: "Remove images", Checked: selected["image:remove"]},
				{Name: "image:build", DisplayName: "Build images", Checked: selected["image:build"]},
			},
		},
		{
			Name:     "Volumes",
			Category: "volume",
			Permissions: []admin.PermissionData{
				{Name: "volume:view", DisplayName: "View volumes", Checked: selected["volume:view"]},
				{Name: "volume:create", DisplayName: "Create volumes", Checked: selected["volume:create"]},
				{Name: "volume:remove", DisplayName: "Remove volumes", Checked: selected["volume:remove"]},
			},
		},
		{
			Name:     "Networks",
			Category: "network",
			Permissions: []admin.PermissionData{
				{Name: "network:view", DisplayName: "View networks", Checked: selected["network:view"]},
				{Name: "network:create", DisplayName: "Create networks", Checked: selected["network:create"]},
				{Name: "network:remove", DisplayName: "Remove networks", Checked: selected["network:remove"]},
			},
		},
		{
			Name:     "Stacks",
			Category: "stack",
			Permissions: []admin.PermissionData{
				{Name: "stack:view", DisplayName: "View stacks", Checked: selected["stack:view"]},
				{Name: "stack:deploy", DisplayName: "Deploy stacks", Checked: selected["stack:deploy"]},
				{Name: "stack:update", DisplayName: "Update stacks", Checked: selected["stack:update"]},
				{Name: "stack:remove", DisplayName: "Remove stacks", Checked: selected["stack:remove"]},
			},
		},
		{
			Name:     "Hosts",
			Category: "host",
			Permissions: []admin.PermissionData{
				{Name: "host:view", DisplayName: "View hosts", Checked: selected["host:view"]},
				{Name: "host:create", DisplayName: "Add hosts", Checked: selected["host:create"]},
				{Name: "host:update", DisplayName: "Update hosts", Checked: selected["host:update"]},
				{Name: "host:remove", DisplayName: "Remove hosts", Checked: selected["host:remove"]},
			},
		},
		{
			Name:     "Users",
			Category: "user",
			Permissions: []admin.PermissionData{
				{Name: "user:view", DisplayName: "View users", Checked: selected["user:view"]},
				{Name: "user:create", DisplayName: "Create users", Checked: selected["user:create"]},
				{Name: "user:update", DisplayName: "Update users", Checked: selected["user:update"]},
				{Name: "user:remove", DisplayName: "Remove users", Checked: selected["user:remove"]},
			},
		},
		{
			Name:     "Roles",
			Category: "role",
			Permissions: []admin.PermissionData{
				{Name: "role:view", DisplayName: "View roles", Checked: selected["role:view"]},
				{Name: "role:create", DisplayName: "Create roles", Checked: selected["role:create"]},
				{Name: "role:update", DisplayName: "Update roles", Checked: selected["role:update"]},
				{Name: "role:remove", DisplayName: "Remove roles", Checked: selected["role:remove"]},
			},
		},
		{
			Name:     "Settings",
			Category: "settings",
			Permissions: []admin.PermissionData{
				{Name: "settings:view", DisplayName: "View settings", Checked: selected["settings:view"]},
				{Name: "settings:update", DisplayName: "Update settings", Checked: selected["settings:update"]},
			},
		},
		{
			Name:     "Backups",
			Category: "backup",
			Permissions: []admin.PermissionData{
				{Name: "backup:view", DisplayName: "View backups", Checked: selected["backup:view"]},
				{Name: "backup:create", DisplayName: "Create backups", Checked: selected["backup:create"]},
				{Name: "backup:restore", DisplayName: "Restore backups", Checked: selected["backup:restore"]},
			},
		},
		{
			Name:     "Security",
			Category: "security",
			Permissions: []admin.PermissionData{
				{Name: "security:view", DisplayName: "View security", Checked: selected["security:view"]},
				{Name: "security:scan", DisplayName: "Run scans", Checked: selected["security:scan"]},
			},
		},
		{
			Name:     "Config",
			Category: "config",
			Permissions: []admin.PermissionData{
				{Name: "config:view", DisplayName: "View config", Checked: selected["config:view"]},
				{Name: "config:create", DisplayName: "Create config", Checked: selected["config:create"]},
				{Name: "config:update", DisplayName: "Update config", Checked: selected["config:update"]},
				{Name: "config:remove", DisplayName: "Remove config", Checked: selected["config:remove"]},
			},
		},
		{
			Name:     "Audit",
			Category: "audit",
			Permissions: []admin.PermissionData{
				{Name: "audit:view", DisplayName: "View audit logs", Checked: selected["audit:view"]},
			},
		},
	}

	return categories
}
