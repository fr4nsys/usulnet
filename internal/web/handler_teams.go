// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/teams"
)

// ============================================================================
// Teams List
// ============================================================================

func (h *Handler) TeamsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Teams", "teams")

	var items []teams.TeamItem
	var stats teams.TeamStats

	teamList, err := h.services.Teams().ListTeams(ctx)
	if err != nil {
		slog.Error("Failed to list teams", "error", err)
	} else {
		stats.Total = len(teamList)
		for _, t := range teamList {
			item := teams.TeamItem{
				ID:              t.ID.String(),
				Name:            t.Name,
				MemberCount:     t.MemberCount,
				PermissionCount: t.PermissionCount,
				CreatedAt:       t.CreatedAt.Format("2006-01-02 15:04"),
			}
			if t.Description != nil {
				item.Description = *t.Description
			}
			if t.CreatedBy != nil {
				if creator, err := h.services.Users().Get(ctx, t.CreatedBy.String()); err == nil && creator != nil {
					item.CreatedBy = creator.Username
				}
			}
			items = append(items, item)

			if t.MemberCount > 0 {
				stats.WithMembers++
			}
			if t.PermissionCount > 0 {
				stats.WithPermissions++
			}
			stats.TotalMembers += t.MemberCount
		}
	}

	data := teams.TeamsData{
		PageData: pageData,
		Teams:    items,
		Stats:    stats,
	}
	h.renderTempl(w, r, teams.List(data))
}

// ============================================================================
// Teams Create
// ============================================================================

func (h *Handler) TeamNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Team", "teams")
	data := teams.TeamNewData{PageData: pageData}
	h.renderTempl(w, r, teams.New(data))
}

func (h *Handler) TeamCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/teams/new")
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")

	if name == "" {
		h.setFlash(w, r, "error", "Team name is required")
		h.redirect(w, r, "/teams/new")
		return
	}

	var createdBy uuid.UUID
	user := GetUserFromContext(ctx)
	if user != nil {
		createdBy, _ = uuid.Parse(user.ID)
	}

	_, err := h.services.Teams().CreateTeam(ctx, name, description, createdBy)
	if err != nil {
		slog.Error("Failed to create team", "name", name, "error", err)
		h.setFlash(w, r, "error", "Failed to create team: "+err.Error())
		h.redirect(w, r, "/teams/new")
		return
	}

	h.setFlash(w, r, "success", "Team created successfully")
	h.redirect(w, r, "/teams")
}

// ============================================================================
// Teams Detail
// ============================================================================

func (h *Handler) TeamDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	tab := r.URL.Query().Get("tab")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The team ID is not valid.")
		return
	}

	team, err := h.services.Teams().GetTeam(ctx, teamID)
	if err != nil || team == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Team not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, team.Name, "teams")

	teamItem := teams.TeamItem{
		ID:              team.ID.String(),
		Name:            team.Name,
		MemberCount:     team.MemberCount,
		PermissionCount: team.PermissionCount,
		CreatedAt:       team.CreatedAt.Format("2006-01-02 15:04"),
		UpdatedAt:       team.UpdatedAt.Format("2006-01-02 15:04"),
	}
	if team.Description != nil {
		teamItem.Description = *team.Description
	}
	if team.CreatedBy != nil {
		if creator, err := h.services.Users().Get(ctx, team.CreatedBy.String()); err == nil && creator != nil {
			teamItem.CreatedBy = creator.Username
		}
	}

	// Fetch members
	var memberItems []teams.MemberItem
	members, err := h.services.Teams().ListMembers(ctx, teamID)
	if err != nil {
		slog.Error("Failed to list team members", "team_id", teamID, "error", err)
	} else {
		for _, m := range members {
			memberItems = append(memberItems, teams.MemberItem{
				UserID:   m.UserID.String(),
				Username: m.Username,
				Email:    m.Email,
				Role:     string(m.RoleInTeam),
				AddedAt:  m.AddedAt.Format("2006-01-02 15:04"),
			})
		}
	}

	// Fetch permissions
	var permItems []teams.PermissionItem
	perms, err := h.services.Teams().ListPermissions(ctx, teamID)
	if err != nil {
		slog.Error("Failed to list team permissions", "team_id", teamID, "error", err)
	} else {
		for _, p := range perms {
			permItems = append(permItems, teams.PermissionItem{
				ID:           p.ID.String(),
				ResourceType: string(p.ResourceType),
				ResourceID:   p.ResourceID,
				ResourceName: p.ResourceName,
				AccessLevel:  string(p.AccessLevel),
				GrantedAt:    p.GrantedAt.Format("2006-01-02 15:04"),
			})
		}
	}

	// Fetch all users for the add-member dropdown
	var userOptions []teams.UserOption
	if userList, _, err := h.services.Users().List(ctx, "", ""); err == nil {
		for _, u := range userList {
			userOptions = append(userOptions, teams.UserOption{
				ID:       u.ID,
				Username: u.Username,
				Email:    u.Email,
			})
		}
	}

	if tab == "" {
		tab = "members"
	}

	// Fetch available resources for permission assignment
	var availableStacks []teams.ResourceOption
	if stackList, err := h.services.Stacks().List(ctx); err == nil {
		for _, s := range stackList {
			availableStacks = append(availableStacks, teams.ResourceOption{
				ID:   s.ID,
				Name: s.Name,
			})
		}
	}

	var availableHosts []teams.ResourceOption
	if hostList, err := h.services.Hosts().List(ctx); err == nil {
		for _, h := range hostList {
			availableHosts = append(availableHosts, teams.ResourceOption{
				ID:   h.ID,
				Name: h.Name,
			})
		}
	}

	var availableNetworks []teams.ResourceOption
	if networkList, err := h.services.Networks().List(ctx); err == nil {
		for _, n := range networkList {
			availableNetworks = append(availableNetworks, teams.ResourceOption{
				ID:   n.ID,
				Name: n.Name,
			})
		}
	}

	var availableVolumes []teams.ResourceOption
	if volumeList, err := h.services.Volumes().List(ctx); err == nil {
		for _, v := range volumeList {
			availableVolumes = append(availableVolumes, teams.ResourceOption{
				ID:   v.Name, // Volumes use name as ID
				Name: v.Name,
			})
		}
	}

	var availableGiteaConns []teams.ResourceOption
	if giteaSvc := h.services.Gitea(); giteaSvc != nil {
		if giteaList, err := giteaSvc.ListAllConnections(ctx); err == nil {
			for _, g := range giteaList {
				availableGiteaConns = append(availableGiteaConns, teams.ResourceOption{
					ID:   g.ID.String(),
					Name: g.Name,
				})
			}
		}
	}

	var availableS3Conns []teams.ResourceOption
	if storageSvc := h.services.Storage(); storageSvc != nil {
		if s3List, err := storageSvc.ListConnections(ctx); err == nil {
			for _, s := range s3List {
				availableS3Conns = append(availableS3Conns, teams.ResourceOption{
					ID:   s.ID,
					Name: s.Name,
				})
			}
		}
	}

	data := teams.TeamDetailData{
		PageData:            pageData,
		Team:                teamItem,
		Members:             memberItems,
		Permissions:         permItems,
		AllUsers:            userOptions,
		Tab:                 tab,
		AvailableStacks:     availableStacks,
		AvailableHosts:      availableHosts,
		AvailableNetworks:   availableNetworks,
		AvailableVolumes:    availableVolumes,
		AvailableGiteaConns: availableGiteaConns,
		AvailableS3Conns:    availableS3Conns,
	}
	h.renderTempl(w, r, teams.Detail(data))
}

// ============================================================================
// Teams Edit
// ============================================================================

func (h *Handler) TeamEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The team ID is not valid.")
		return
	}

	team, err := h.services.Teams().GetTeam(ctx, teamID)
	if err != nil || team == nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Team not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Team", "teams")

	item := teams.TeamItem{
		ID:        team.ID.String(),
		Name:      team.Name,
		CreatedAt: team.CreatedAt.Format("2006-01-02 15:04"),
	}
	if team.Description != nil {
		item.Description = *team.Description
	}

	data := teams.TeamEditData{
		PageData: pageData,
		Team:     item,
	}
	h.renderTempl(w, r, teams.Edit(data))
}

func (h *Handler) TeamUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/teams")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/teams/"+idStr+"/edit")
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")

	if name == "" {
		h.setFlash(w, r, "error", "Team name is required")
		h.redirect(w, r, "/teams/"+idStr+"/edit")
		return
	}

	_, err = h.services.Teams().UpdateTeam(ctx, teamID, name, description)
	if err != nil {
		slog.Error("Failed to update team", "id", teamID, "error", err)
		h.setFlash(w, r, "error", "Failed to update team: "+err.Error())
		h.redirect(w, r, "/teams/"+idStr+"/edit")
		return
	}

	h.redirect(w, r, "/teams/"+idStr)
}

// ============================================================================
// Teams Delete
// ============================================================================

func (h *Handler) TeamDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/teams")
		return
	}

	if err := h.services.Teams().DeleteTeam(ctx, teamID); err != nil {
		slog.Error("Failed to delete team", "id", teamID, "error", err)
		h.setFlash(w, r, "error", "Failed to delete team: "+err.Error())
		h.redirect(w, r, "/teams")
		return
	}

	h.setFlash(w, r, "success", "Team deleted successfully")
	h.redirect(w, r, "/teams")
}

// ============================================================================
// Team Members
// ============================================================================

func (h *Handler) TeamAddMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/teams")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/teams/"+idStr+"?tab=members")
		return
	}

	userIDStr := r.FormValue("user_id")
	roleStr := r.FormValue("role")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Error("Invalid user ID", "user_id", userIDStr, "error", err)
		h.redirect(w, r, "/teams/"+idStr+"?tab=members")
		return
	}

	role := models.TeamRole(roleStr)
	if !role.IsValid() {
		role = models.TeamRoleMember
	}

	var addedBy uuid.UUID
	user := GetUserFromContext(ctx)
	if user != nil {
		addedBy, _ = uuid.Parse(user.ID)
	}

	if err := h.services.Teams().AddMember(ctx, teamID, userID, role, addedBy); err != nil {
		slog.Error("Failed to add team member", "team_id", teamID, "user_id", userID, "error", err)
		h.setFlash(w, r, "error", "Failed to add member: "+err.Error())
		h.redirect(w, r, "/teams/"+idStr+"?tab=members")
		return
	}

	h.setFlash(w, r, "success", "Member added to team")
	h.redirect(w, r, "/teams/"+idStr+"?tab=members")
}

func (h *Handler) TeamRemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	userIDStr := chi.URLParam(r, "userID")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/teams")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.redirect(w, r, "/teams/"+idStr+"?tab=members")
		return
	}

	if err := h.services.Teams().RemoveMember(ctx, teamID, userID); err != nil {
		slog.Error("Failed to remove team member", "team_id", teamID, "user_id", userID, "error", err)
		h.setFlash(w, r, "error", "Failed to remove member: "+err.Error())
		h.redirect(w, r, "/teams/"+idStr+"?tab=members")
		return
	}

	h.setFlash(w, r, "success", "Member removed from team")
	h.redirect(w, r, "/teams/"+idStr+"?tab=members")
}

// ============================================================================
// Team Permissions
// ============================================================================

func (h *Handler) TeamGrantPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	teamID, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/teams")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	resourceTypeStr := r.FormValue("resource_type")
	resourceID := r.FormValue("resource_id")
	accessLevelStr := r.FormValue("access_level")

	resourceType := models.ResourceType(resourceTypeStr)
	if !resourceType.IsValid() {
		slog.Error("Invalid resource type", "resource_type", resourceTypeStr)
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	if resourceID == "" {
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	accessLevel := models.AccessLevel(accessLevelStr)
	if !accessLevel.IsValid() {
		accessLevel = models.AccessLevelView
	}

	var grantedBy uuid.UUID
	user := GetUserFromContext(ctx)
	if user != nil {
		grantedBy, _ = uuid.Parse(user.ID)
	}

	if err := h.services.Teams().GrantAccess(ctx, teamID, resourceType, resourceID, accessLevel, grantedBy); err != nil {
		slog.Error("Failed to grant permission", "team_id", teamID, "resource_type", resourceType, "resource_id", resourceID, "error", err)
		h.setFlash(w, r, "error", "Failed to grant permission: "+err.Error())
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	h.setFlash(w, r, "success", "Permission granted")
	h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
}

func (h *Handler) TeamRevokePermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	permIDStr := chi.URLParam(r, "permID")

	permID, err := uuid.Parse(permIDStr)
	if err != nil {
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	if err := h.services.Teams().RevokeAccessByID(ctx, permID); err != nil {
		slog.Error("Failed to revoke permission", "perm_id", permID, "error", err)
		h.setFlash(w, r, "error", "Failed to revoke permission: "+err.Error())
		h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
		return
	}

	h.setFlash(w, r, "success", "Permission revoked")
	h.redirect(w, r, "/teams/"+idStr+"?tab=permissions")
}
