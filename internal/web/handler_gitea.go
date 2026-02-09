// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/integrations/gitea"
	giteapages "github.com/fr4nsys/usulnet/internal/web/templates/pages/gitea"
)

// ============================================================================
// Page handlers (render templ templates)
// ============================================================================

// GiteaTempl renders the Gitea integrations page listing connections and repos.
// GET /integrations/gitea
func (h *Handler) GiteaTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "Git Integration", "")
		return
	}

	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Gitea Integration", "gitea")

	connections, err := svc.ListAllConnections(ctx)
	if err != nil {
		slog.Error("failed to list gitea connections", "error", err)
		h.setFlash(w, r, "error", "Failed to list connections: "+err.Error())
	}

	var conns []giteapages.ConnectionItem
	var repos []giteapages.RepoItem
	var stats giteapages.GiteaStats

	stats.TotalConnections = len(connections)

	for _, c := range connections {
		cd := giteapages.ConnectionItem{
			ID:         c.ID.String(),
			Name:       c.Name,
			URL:        c.URL,
			Status:     string(c.Status),
			ReposCount: c.ReposCount,
			AutoSync:   c.AutoSync,
		}
		if c.StatusMessage != nil {
			cd.StatusMsg = *c.StatusMessage
		}
		if c.GiteaVersion != nil {
			cd.ProviderVersion = *c.GiteaVersion
		}
		if c.Status == "connected" {
			stats.ActiveConnections++
		}
		conns = append(conns, cd)

		// Fetch repos for this connection
		connRepos, err := svc.ListRepositories(ctx, c.ID)
		if err != nil {
			slog.Error("failed to list repos", "conn_id", c.ID, "error", err)
			continue
		}
		for _, repo := range connRepos {
			rd := giteapages.RepoItem{
				ID:             repo.ID.String(),
				ConnectionID:   c.ID.String(),
				ConnectionName: c.Name,
				FullName:       repo.FullName,
				DefaultBranch:  repo.DefaultBranch,
				IsPrivate:      repo.IsPrivate,
				IsFork:         repo.IsFork,
				IsArchived:     repo.IsArchived,
				Stars:          repo.StarsCount,
				Forks:          repo.ForksCount,
				HTMLURL:        repo.HTMLURL,
			}
			if repo.Description != nil {
				rd.Description = *repo.Description
			}
			repos = append(repos, rd)
			stats.TotalRepos++
			if repo.IsPrivate {
				stats.PrivateRepos++
			}
		}
	}

	// Get CSRF token from context
	csrfToken := ""
	if token, ok := ctx.Value("csrf_token").(string); ok {
		csrfToken = token
	}

	data := giteapages.GiteaData{
		PageData:    pageData,
		Connections: conns,
		Repos:       repos,
		Stats:       stats,
		CSRFToken:   csrfToken,
	}
	h.renderTempl(w, r, giteapages.List(data))
}

// GiteaRepoDetail renders the repo detail page with branches and recent commits.
// GET /integrations/gitea/repos/{id}
func (h *Handler) GiteaRepoDetail(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "Git Integration", "")
		return
	}

	ctx := r.Context()
	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	ref := r.URL.Query().Get("ref")
	path := r.URL.Query().Get("path")

	repo, err := svc.GetRepository(ctx, repoID)
	if err != nil {
		h.setFlash(w, r, "error", "Repository not found: "+err.Error())
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	if ref == "" {
		ref = repo.DefaultBranch
	}

	// Fetch branches, tags, commits, files
	branches, _ := svc.ListBranches(ctx, repoID)
	tags, _ := svc.ListTags(ctx, repoID, 1, 50)
	commits, _ := svc.ListCommits(ctx, repoID, ref, 20)
	files, _ := svc.ListFiles(ctx, repoID, path, ref)

	// Map branches to template types
	var branchItems []giteapages.BranchItem
	for _, b := range branches {
		branchItems = append(branchItems, giteapages.BranchItem{
			Name:      b.Name,
			IsDefault: b.Name == repo.DefaultBranch,
			Protected: b.Protected,
		})
	}

	// Map tags to template types
	var tagItems []giteapages.TagItem
	for _, t := range tags {
		tagItems = append(tagItems, giteapages.TagItem{
			Name:    t.Name,
			SHA:     t.ID,
			Message: t.Message,
		})
	}

	// Map commits to template types
	var commitItems []giteapages.CommitItem
	for _, c := range commits {
		shortSHA := c.SHA
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		commitItems = append(commitItems, giteapages.CommitItem{
			SHA:      c.SHA,
			Message:  c.Commit.Message,
			Author:   commitAuthorName(c),
			Date:     commitDate(c),
			ShortSHA: shortSHA,
		})
	}

	// Map files to template types
	var fileItems []giteapages.FileItem
	for _, f := range files {
		fileItems = append(fileItems, giteapages.FileItem{
			Name: f.Name,
			Path: f.Path,
			Type: f.Type,
			Size: f.Size,
			SHA:  f.SHA,
		})
	}

	// Find connection info
	connName := ""
	connID := ""
	if repo.ConnectionID != uuid.Nil {
		conn, err := svc.GetConnection(ctx, repo.ConnectionID)
		if err == nil {
			connName = conn.Name
			connID = conn.ID.String()
		}
	}

	pageData := h.prepareTemplPageData(r, repo.FullName, "gitea")

	detail := giteapages.RepoDetail{
		ID:             repo.ID.String(),
		ConnectionID:   connID,
		ConnectionName: connName,
		FullName:       repo.FullName,
		DefaultBranch:  repo.DefaultBranch,
		IsPrivate:      repo.IsPrivate,
		IsFork:         repo.IsFork,
		IsArchived:     repo.IsArchived,
		Stars:          repo.StarsCount,
		Forks:          repo.ForksCount,
		HTMLURL:        repo.HTMLURL,
	}
	if repo.Description != nil {
		detail.Description = *repo.Description
	}

	// Get CSRF token from context
	csrfToken := ""
	if token, ok := ctx.Value("csrf_token").(string); ok {
		csrfToken = token
	}

	data := giteapages.RepoDetailData{
		PageData:      pageData,
		Repo:          detail,
		Branches:      branchItems,
		Tags:          tagItems,
		Commits:       commitItems,
		Files:         fileItems,
		CurrentBranch: ref,
		CurrentPath:   path,
		CSRFToken:     csrfToken,
	}
	h.renderTempl(w, r, giteapages.Detail(data))
}

// GiteaPullRequestsPage renders the pull requests list page.
// GET /integrations/gitea/repos/{id}/pulls
func (h *Handler) GiteaPullRequestsPage(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Pull Requests", "gitea")
	csrfToken := h.getCSRFToken(r)

	repo, err := svc.GetRepository(ctx, repoID)
	if err != nil {
		slog.Error("failed to get repository", "error", err)
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	conn, err := svc.GetConnection(ctx, repo.ConnectionID)
	if err != nil {
		slog.Error("failed to get connection", "error", err)
	}

	// Get filter state
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}

	// Fetch PRs
	prs, err := svc.ListPullRequests(ctx, repoID, gitea.PRListOptions{State: state, Limit: 50})
	if err != nil {
		slog.Error("failed to list pull requests", "error", err)
	}

	// Count open/closed
	openPRs, _ := svc.ListPullRequests(ctx, repoID, gitea.PRListOptions{State: "open", Limit: 1})
	closedPRs, _ := svc.ListPullRequests(ctx, repoID, gitea.PRListOptions{State: "closed", Limit: 1})

	// Fetch branches for create PR modal
	branches, _ := svc.ListBranches(ctx, repoID)

	var prItems []giteapages.PRItem
	for _, pr := range prs {
		prItems = append(prItems, giteapages.PRItem{
			Number:    pr.Number,
			Title:     pr.Title,
			State:     pr.State,
			User:      pr.User.Login,
			CreatedAt: pr.CreatedAt.Format("2006-01-02"),
			Comments:  pr.Comments,
			Merged:    pr.Merged,
			HeadRef:   pr.Head.Ref,
			BaseRef:   pr.Base.Ref,
		})
	}

	var branchItems []giteapages.BranchItem
	for _, b := range branches {
		branchItems = append(branchItems, giteapages.BranchItem{
			Name:      b.Name,
			IsDefault: b.Name == repo.DefaultBranch,
			Protected: b.Protected,
		})
	}

	connName := ""
	if conn != nil {
		connName = conn.Name
	}

	desc := ""
	if repo.Description != nil {
		desc = *repo.Description
	}

	data := giteapages.PRListData{
		PageData:    pageData,
		Repo:        giteapages.RepoDetail{
			ID:             repo.ID.String(),
			ConnectionID:   repo.ConnectionID.String(),
			ConnectionName: connName,
			FullName:       repo.FullName,
			Description:    desc,
			DefaultBranch:  repo.DefaultBranch,
			IsPrivate:      repo.IsPrivate,
			IsFork:         repo.IsFork,
			IsArchived:     repo.IsArchived,
			HTMLURL:        repo.HTMLURL,
		},
		PRs:         prItems,
		State:       state,
		CSRFToken:   csrfToken,
		Branches:    branchItems,
		OpenCount:   len(openPRs),
		ClosedCount: len(closedPRs),
	}
	h.renderTempl(w, r, giteapages.PullRequestsList(data))
}

// GiteaIssuesPage renders the issues list page.
// GET /integrations/gitea/repos/{id}/issues
func (h *Handler) GiteaIssuesPage(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Issues", "gitea")
	csrfToken := h.getCSRFToken(r)

	repo, err := svc.GetRepository(ctx, repoID)
	if err != nil {
		slog.Error("failed to get repository", "error", err)
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	conn, err := svc.GetConnection(ctx, repo.ConnectionID)
	if err != nil {
		slog.Error("failed to get connection", "error", err)
	}

	// Get filter state
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}

	// Fetch issues
	issues, err := svc.ListIssues(ctx, repoID, gitea.IssueListOptions{State: state, Limit: 50})
	if err != nil {
		slog.Error("failed to list issues", "error", err)
	}

	// Count open/closed
	openIssues, _ := svc.ListIssues(ctx, repoID, gitea.IssueListOptions{State: "open", Limit: 1})
	closedIssues, _ := svc.ListIssues(ctx, repoID, gitea.IssueListOptions{State: "closed", Limit: 1})

	// Fetch labels for create issue modal
	labels, _ := svc.ListLabels(ctx, repoID)
	milestones, _ := svc.ListMilestones(ctx, repoID, "")

	var issueItems []giteapages.IssueItem
	for _, issue := range issues {
		var lblItems []giteapages.LabelItem
		for _, l := range issue.Labels {
			lblItems = append(lblItems, giteapages.LabelItem{
				ID:    l.ID,
				Name:  l.Name,
				Color: l.Color,
			})
		}
		issueItems = append(issueItems, giteapages.IssueItem{
			Number:    issue.Number,
			Title:     issue.Title,
			State:     issue.State,
			User:      issue.User.Login,
			CreatedAt: issue.CreatedAt.Format("2006-01-02"),
			Comments:  issue.Comments,
			Labels:    lblItems,
		})
	}

	var labelItems []giteapages.LabelItem
	for _, l := range labels {
		labelItems = append(labelItems, giteapages.LabelItem{
			ID:    l.ID,
			Name:  l.Name,
			Color: l.Color,
		})
	}

	var milestoneItems []giteapages.MilestoneItem
	for _, m := range milestones {
		milestoneItems = append(milestoneItems, giteapages.MilestoneItem{
			ID:    m.ID,
			Title: m.Title,
			State: m.State,
		})
	}

	connName := ""
	if conn != nil {
		connName = conn.Name
	}

	issueDesc := ""
	if repo.Description != nil {
		issueDesc = *repo.Description
	}

	data := giteapages.IssueListData{
		PageData:    pageData,
		Repo:        giteapages.RepoDetail{
			ID:             repo.ID.String(),
			ConnectionID:   repo.ConnectionID.String(),
			ConnectionName: connName,
			FullName:       repo.FullName,
			Description:    issueDesc,
			DefaultBranch:  repo.DefaultBranch,
			IsPrivate:      repo.IsPrivate,
			IsFork:         repo.IsFork,
			IsArchived:     repo.IsArchived,
			HTMLURL:        repo.HTMLURL,
		},
		Issues:      issueItems,
		State:       state,
		CSRFToken:   csrfToken,
		Labels:      labelItems,
		Milestones:  milestoneItems,
		OpenCount:   len(openIssues),
		ClosedCount: len(closedIssues),
	}
	h.renderTempl(w, r, giteapages.IssuesList(data))
}

// ============================================================================
// HTMX partial handlers (return JSON/HTML fragments)
// ============================================================================

// GiteaRepoFiles returns the file tree for a path in a repo.
// GET /integrations/gitea/repos/{id}/files?path=&ref=
func (h *Handler) GiteaRepoFiles(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	ref := r.URL.Query().Get("ref")

	files, err := svc.ListFiles(r.Context(), repoID, path, ref)
	if err != nil {
		http.Error(w, "Failed to list files: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to template types and render partial
	var fileItems []giteapages.FileItem
	for _, f := range files {
		fileItems = append(fileItems, giteapages.FileItem{
			Name: f.Name,
			Path: f.Path,
			Type: f.Type,
			Size: f.Size,
			SHA:  f.SHA,
		})
	}

	// Render the file list partial as HTML for HTMX
	h.renderTempl(w, r, giteapages.FileListPartial(fileItems, repoID.String(), ref))
}

// GiteaFileContent returns the content of a single file.
// GET /integrations/gitea/repos/{id}/file?path=&ref=
func (h *Handler) GiteaFileContent(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	ref := r.URL.Query().Get("ref")

	if path == "" {
		http.Error(w, "path parameter required", http.StatusBadRequest)
		return
	}

	content, err := svc.GetFileContent(r.Context(), repoID, path, ref)
	if err != nil {
		http.Error(w, "Failed to get file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Detect if binary by checking for null bytes in first 8KB
	sample := content
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	isBinary := false
	for _, b := range sample {
		if b == 0 {
			isBinary = true
			break
		}
	}

	if isBinary {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+sanitizeFilename(path))
		w.Write(content)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

// GiteaFileSave saves (commits) a file to Gitea.
// POST /integrations/gitea/repos/{id}/file
func (h *Handler) GiteaFileSave(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	path := r.FormValue("path")
	ref := r.FormValue("ref")
	content := r.FormValue("content")
	message := r.FormValue("message")

	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	if message == "" {
		user := GetUserFromContext(r.Context())
		userName := "usulnet"
		if user != nil {
			userName = user.Username
		}
		message = "Update " + path + " via usulnet (" + userName + ")"
	}

	if err := svc.UpdateFile(r.Context(), repoID, path, ref, content, message); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ============================================================================
// Connection action handlers
// ============================================================================

// GiteaCreateConnection handles POST /integrations/gitea/connections.
func (h *Handler) GiteaCreateConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	url := strings.TrimSpace(r.FormValue("url"))
	apiToken := strings.TrimSpace(r.FormValue("api_token"))
	webhookSecret := strings.TrimSpace(r.FormValue("webhook_secret"))

	if name == "" || url == "" || apiToken == "" {
		h.setFlash(w, r, "error", "Name, URL and API token are required")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	// Get current user
	user := GetUserFromContext(r.Context())
	var createdBy uuid.UUID
	if user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			createdBy = parsed
		}
	}

	// Get host ID (use default host for now)
	hostID := h.getDefaultHostID(r)

	input := &gitea.CreateConnectionInput{
		HostID:        hostID,
		Name:          name,
		URL:           url,
		APIToken:      apiToken,
		WebhookSecret: webhookSecret,
		CreatedBy:     createdBy,
	}

	if _, err := svc.CreateConnection(r.Context(), input); err != nil {
		h.setFlash(w, r, "error", "Failed to create connection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Gitea connection '"+name+"' created")
	}

	http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
}

// GiteaTestConnection handles POST /integrations/gitea/connections/{id}/test.
func (h *Handler) GiteaTestConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	connID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	result, err := svc.TestConnection(r.Context(), connID)
	if err != nil {
		h.setFlash(w, r, "error", "Test failed: "+err.Error())
	} else if !result.Success {
		h.setFlash(w, r, "error", "Test failed: "+result.Error)
	} else {
		msg := "Connected! Gitea " + result.Version + " (user: " + result.Username + ")"
		h.setFlash(w, r, "success", msg)
	}

	http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
}

// GiteaSyncRepos handles POST /integrations/gitea/connections/{id}/sync.
func (h *Handler) GiteaSyncRepos(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	connID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	count, err := svc.SyncRepositories(r.Context(), connID)
	if err != nil {
		h.setFlash(w, r, "error", "Sync failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Synced "+strconv.Itoa(count)+" repositories")
	}

	http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
}

// GiteaDeleteConnection handles POST /integrations/gitea/connections/{id}/delete.
func (h *Handler) GiteaDeleteConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	connID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.setFlash(w, r, "error", "Invalid connection ID")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	if err := svc.DeleteConnection(r.Context(), connID); err != nil {
		h.setFlash(w, r, "error", "Failed to delete: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection deleted")
	}

	http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
}

// ============================================================================
// Webhook receiver (public endpoint, no auth)
// ============================================================================

// GiteaWebhookReceiver handles POST /webhooks/gitea.
// Validates HMAC-SHA256 signature and stores the event.
func (h *Handler) GiteaWebhookReceiver(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Gitea integration not configured", http.StatusServiceUnavailable)
		return
	}

	// Read body (limit to 5MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Extract Gitea headers
	eventType := r.Header.Get("X-Gitea-Event")
	deliveryID := r.Header.Get("X-Gitea-Delivery")
	signature := r.Header.Get("X-Gitea-Signature")

	if eventType == "" {
		http.Error(w, "Missing X-Gitea-Event header", http.StatusBadRequest)
		return
	}

	// Try to resolve which connection this webhook belongs to.
	connID := h.resolveWebhookConnection(r.Context(), svc, body, signature)
	if connID == uuid.Nil {
		slog.Warn("webhook received but no matching connection found",
			"event", eventType, "delivery", deliveryID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "no_matching_connection"})
		return
	}

	// Validate signature if webhook secret is configured
	secret, _ := svc.GetWebhookSecret(r.Context(), connID)
	if secret != "" {
		if !gitea.ValidateWebhookSignature(secret, body, signature) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Store and process
	if err := svc.HandleWebhook(r.Context(), connID, eventType, deliveryID, body); err != nil {
		slog.Error("failed to handle webhook", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// resolveWebhookConnection tries to find which connection a webhook belongs to.
func (h *Handler) resolveWebhookConnection(ctx context.Context, svc GiteaService, payload []byte, signature string) uuid.UUID {
	var partial struct {
		Repository struct {
			HTMLURL string `json:"html_url"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(payload, &partial); err != nil || partial.Repository.HTMLURL == "" {
		return uuid.Nil
	}

	connections, err := svc.ListAllConnections(ctx)
	if err != nil || len(connections) == 0 {
		return uuid.Nil
	}

	repoURL := strings.ToLower(partial.Repository.HTMLURL)
	for _, conn := range connections {
		connURL := strings.ToLower(strings.TrimRight(conn.URL, "/"))
		if strings.HasPrefix(repoURL, connURL) {
			return conn.ID
		}
	}

	// Fallback: if only one connection exists, use it
	if len(connections) == 1 {
		return connections[0].ID
	}

	return uuid.Nil
}

// ============================================================================
// Tier 1: Repository Management
// ============================================================================

// GiteaCreateRepo creates a new repository.
// POST /integrations/gitea/repos
func (h *Handler) GiteaCreateRepo(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		h.RenderError(w, r, http.StatusServiceUnavailable, "Error", "Git integration not configured")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid form data")
		return
	}

	connIDStr := r.FormValue("connection_id")
	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid connection ID")
		return
	}

	input := &gitea.CreateRepositoryInput{
		ConnectionID:  connID,
		Name:          r.FormValue("name"),
		Description:   r.FormValue("description"),
		Private:       r.FormValue("private") == "true" || r.FormValue("private") == "on",
		AutoInit:      r.FormValue("auto_init") == "true" || r.FormValue("auto_init") == "on",
		Gitignore:     r.FormValue("gitignore"),
		License:       r.FormValue("license"),
		DefaultBranch: r.FormValue("default_branch"),
	}

	repo, err := svc.CreateRepository(r.Context(), input)
	if err != nil {
		slog.Error("failed to create repository", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to create repository: "+err.Error())
		return
	}

	// Redirect to the new repository
	http.Redirect(w, r, "/integrations/gitea/repos/"+repo.ID.String(), http.StatusSeeOther)
}

// GiteaEditRepo updates repository settings.
// POST /integrations/gitea/repos/{id}/edit
func (h *Handler) GiteaEditRepo(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		h.RenderError(w, r, http.StatusServiceUnavailable, "Error", "Git integration not configured")
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid repository ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid form data")
		return
	}

	input := &gitea.EditRepositoryInput{
		RepoID: repoID,
	}

	// Only set fields that were actually submitted
	if name := r.FormValue("name"); name != "" {
		input.Name = &name
	}
	if desc := r.FormValue("description"); r.Form.Has("description") {
		input.Description = &desc
	}
	if r.Form.Has("private") {
		private := r.FormValue("private") == "true" || r.FormValue("private") == "on"
		input.Private = &private
	}
	if r.Form.Has("archived") {
		archived := r.FormValue("archived") == "true" || r.FormValue("archived") == "on"
		input.Archived = &archived
	}
	if branch := r.FormValue("default_branch"); branch != "" {
		input.DefaultBranch = &branch
	}

	_, err = svc.EditRepository(r.Context(), input)
	if err != nil {
		slog.Error("failed to edit repository", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to edit repository: "+err.Error())
		return
	}

	http.Redirect(w, r, "/integrations/gitea/repos/"+repoIDStr, http.StatusSeeOther)
}

// GiteaDeleteRepo deletes a repository.
// POST /integrations/gitea/repos/{id}/delete
func (h *Handler) GiteaDeleteRepo(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		h.RenderError(w, r, http.StatusServiceUnavailable, "Error", "Git integration not configured")
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		h.RenderError(w, r, http.StatusBadRequest, "Error", "Invalid repository ID")
		return
	}

	if err := svc.DeleteRepository(r.Context(), repoID); err != nil {
		slog.Error("failed to delete repository", "error", err)
		h.RenderError(w, r, http.StatusInternalServerError, "Error", "Failed to delete repository: "+err.Error())
		return
	}

	http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
}

// ============================================================================
// Tier 1: Branch Management
// ============================================================================

// GiteaListBranches returns branches as JSON.
// GET /integrations/gitea/repos/{id}/branches
func (h *Handler) GiteaListBranches(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	branches, err := svc.ListBranches(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list branches", "error", err)
		http.Error(w, "Failed to list branches", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(branches)
}

// GiteaCreateBranch creates a new branch.
// POST /integrations/gitea/repos/{id}/branches
func (h *Handler) GiteaCreateBranch(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var input struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	branch, err := svc.CreateBranch(r.Context(), repoID, input.Name, input.Source)
	if err != nil {
		slog.Error("failed to create branch", "error", err)
		http.Error(w, "Failed to create branch: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(branch)
}

// GiteaDeleteBranch deletes a branch.
// DELETE /integrations/gitea/repos/{id}/branches/{name}
func (h *Handler) GiteaDeleteBranch(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	branchName := chi.URLParam(r, "name")
	if branchName == "" {
		http.Error(w, "Branch name required", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteBranch(r.Context(), repoID, branchName); err != nil {
		slog.Error("failed to delete branch", "error", err)
		http.Error(w, "Failed to delete branch: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Tier 1: Tag Management
// ============================================================================

// GiteaListTags returns tags as JSON.
// GET /integrations/gitea/repos/{id}/tags
func (h *Handler) GiteaListTags(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	tags, err := svc.ListTags(r.Context(), repoID, page, 50)
	if err != nil {
		slog.Error("failed to list tags", "error", err)
		http.Error(w, "Failed to list tags", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tags)
}

// GiteaCreateTag creates a new tag.
// POST /integrations/gitea/repos/{id}/tags
func (h *Handler) GiteaCreateTag(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var input struct {
		Name    string `json:"name"`
		Target  string `json:"target"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	tag, err := svc.CreateTag(r.Context(), repoID, input.Name, input.Target, input.Message)
	if err != nil {
		slog.Error("failed to create tag", "error", err)
		http.Error(w, "Failed to create tag: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tag)
}

// GiteaDeleteTag deletes a tag.
// DELETE /integrations/gitea/repos/{id}/tags/{name}
func (h *Handler) GiteaDeleteTag(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	tagName := chi.URLParam(r, "name")
	if tagName == "" {
		http.Error(w, "Tag name required", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteTag(r.Context(), repoID, tagName); err != nil {
		slog.Error("failed to delete tag", "error", err)
		http.Error(w, "Failed to delete tag: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Tier 1: Commit & Diff
// ============================================================================

// GiteaListCommitsFiltered returns commits with filtering as JSON.
// GET /integrations/gitea/repos/{id}/commits?sha=&path=&author=&since=&until=&page=&limit=
func (h *Handler) GiteaListCommitsFiltered(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	opts := gitea.CommitListOptions{
		SHA:    r.URL.Query().Get("sha"),
		Path:   r.URL.Query().Get("path"),
		Author: r.URL.Query().Get("author"),
		Since:  r.URL.Query().Get("since"),
		Until:  r.URL.Query().Get("until"),
	}

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			opts.Page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			opts.Limit = parsed
		}
	}

	commits, err := svc.ListCommitsFiltered(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to list commits", "error", err)
		http.Error(w, "Failed to list commits", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(commits)
}

// GiteaGetCommit returns a single commit with details.
// GET /integrations/gitea/repos/{id}/commits/{sha}
func (h *Handler) GiteaGetCommit(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	sha := chi.URLParam(r, "sha")
	if sha == "" {
		http.Error(w, "Commit SHA required", http.StatusBadRequest)
		return
	}

	commit, err := svc.GetCommit(r.Context(), repoID, sha)
	if err != nil {
		slog.Error("failed to get commit", "error", err)
		http.Error(w, "Failed to get commit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(commit)
}

// GiteaCompare compares two refs (branches, tags, or commits).
// GET /integrations/gitea/repos/{id}/compare?base=main&head=feature
func (h *Handler) GiteaCompare(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	base := r.URL.Query().Get("base")
	head := r.URL.Query().Get("head")
	if base == "" || head == "" {
		http.Error(w, "base and head query params required", http.StatusBadRequest)
		return
	}

	compare, err := svc.Compare(r.Context(), repoID, base, head)
	if err != nil {
		slog.Error("failed to compare refs", "error", err)
		http.Error(w, "Failed to compare: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(compare)
}

// GiteaGetDiff returns raw diff between two refs.
// GET /integrations/gitea/repos/{id}/diff?base=main&head=feature
func (h *Handler) GiteaGetDiff(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	base := r.URL.Query().Get("base")
	head := r.URL.Query().Get("head")
	if base == "" || head == "" {
		http.Error(w, "base and head query params required", http.StatusBadRequest)
		return
	}

	diff, err := svc.GetDiff(r.Context(), repoID, base, head)
	if err != nil {
		slog.Error("failed to get diff", "error", err)
		http.Error(w, "Failed to get diff: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(diff)
}

// ============================================================================
// Tier 1: Templates (for repo creation)
// ============================================================================

// GiteaTemplates returns gitignore and license templates.
// GET /integrations/gitea/connections/{id}/templates
func (h *Handler) GiteaTemplates(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	connIDStr := chi.URLParam(r, "id")
	connID, err := uuid.Parse(connIDStr)
	if err != nil {
		http.Error(w, "Invalid connection ID", http.StatusBadRequest)
		return
	}

	gitignores, err := svc.ListGitignoreTemplates(r.Context(), connID)
	if err != nil {
		slog.Warn("failed to list gitignore templates", "error", err)
		gitignores = []string{}
	}

	licenses, err := svc.ListLicenseTemplates(r.Context(), connID)
	if err != nil {
		slog.Warn("failed to list license templates", "error", err)
		licenses = []gitea.APILicenseTemplate{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"gitignores": gitignores,
		"licenses":   licenses,
	})
}

// ============================================================================
// Tier 2: Pull Requests
// ============================================================================

// GiteaListPRs returns pull requests for a repository.
// GET /integrations/gitea/repos/{id}/pulls
// If tab=pulls query param or Accept: text/html, renders page; otherwise returns JSON.
func (h *Handler) GiteaListPRs(w http.ResponseWriter, r *http.Request) {
	// Check if this is a page request (tab param or Accept header)
	if r.URL.Query().Get("tab") == "pulls" || strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.GiteaPullRequestsPage(w, r)
		return
	}

	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	opts := gitea.PRListOptions{
		State: r.URL.Query().Get("state"),
		Sort:  r.URL.Query().Get("sort"),
	}
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			opts.Page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			opts.Limit = parsed
		}
	}

	prs, err := svc.ListPullRequests(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to list pull requests", "error", err)
		http.Error(w, "Failed to list pull requests", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(prs)
}

// GiteaGetPR returns a single pull request.
// GET /integrations/gitea/repos/{id}/pulls/{number}
func (h *Handler) GiteaGetPR(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	pr, err := svc.GetPullRequest(r.Context(), repoID, number)
	if err != nil {
		slog.Error("failed to get pull request", "error", err)
		http.Error(w, "Failed to get pull request", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pr)
}

// GiteaCreatePR creates a new pull request.
// POST /integrations/gitea/repos/{id}/pulls
func (h *Handler) GiteaCreatePR(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var opts gitea.CreatePullRequestOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	pr, err := svc.CreatePullRequest(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to create pull request", "error", err)
		http.Error(w, "Failed to create pull request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(pr)
}

// GiteaEditPR updates a pull request.
// PATCH /integrations/gitea/repos/{id}/pulls/{number}
func (h *Handler) GiteaEditPR(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	var opts gitea.EditPullRequestOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	pr, err := svc.EditPullRequest(r.Context(), repoID, number, opts)
	if err != nil {
		slog.Error("failed to edit pull request", "error", err)
		http.Error(w, "Failed to edit pull request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pr)
}

// GiteaMergePR merges a pull request.
// POST /integrations/gitea/repos/{id}/pulls/{number}/merge
func (h *Handler) GiteaMergePR(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	var opts gitea.MergePullRequestOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		// Default to merge if no body
		opts.MergeStyle = "merge"
	}

	if err := svc.MergePullRequest(r.Context(), repoID, number, opts); err != nil {
		slog.Error("failed to merge pull request", "error", err)
		http.Error(w, "Failed to merge: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaGetPRDiff returns the diff for a pull request.
// GET /integrations/gitea/repos/{id}/pulls/{number}/diff
func (h *Handler) GiteaGetPRDiff(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	diff, err := svc.GetPullRequestDiff(r.Context(), repoID, number)
	if err != nil {
		slog.Error("failed to get PR diff", "error", err)
		http.Error(w, "Failed to get diff", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(diff)
}

// GiteaListPRReviews returns reviews for a pull request.
// GET /integrations/gitea/repos/{id}/pulls/{number}/reviews
func (h *Handler) GiteaListPRReviews(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	reviews, err := svc.ListPRReviews(r.Context(), repoID, number)
	if err != nil {
		slog.Error("failed to list PR reviews", "error", err)
		http.Error(w, "Failed to list reviews", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reviews)
}

// GiteaCreatePRReview creates a review on a pull request.
// POST /integrations/gitea/repos/{id}/pulls/{number}/reviews
func (h *Handler) GiteaCreatePRReview(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid PR number", http.StatusBadRequest)
		return
	}

	var opts gitea.CreatePRReviewOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	review, err := svc.CreatePRReview(r.Context(), repoID, number, opts)
	if err != nil {
		slog.Error("failed to create review", "error", err)
		http.Error(w, "Failed to create review: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(review)
}

// ============================================================================
// Tier 2: Issues
// ============================================================================

// GiteaListIssues returns issues for a repository.
// GET /integrations/gitea/repos/{id}/issues
// If tab=issues query param or Accept: text/html, renders page; otherwise returns JSON.
func (h *Handler) GiteaListIssues(w http.ResponseWriter, r *http.Request) {
	// Check if this is a page request (tab param or Accept header)
	if r.URL.Query().Get("tab") == "issues" || strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.GiteaIssuesPage(w, r)
		return
	}

	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	opts := gitea.IssueListOptions{
		State:    r.URL.Query().Get("state"),
		Labels:   r.URL.Query().Get("labels"),
		Assignee: r.URL.Query().Get("assignee"),
	}
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			opts.Page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			opts.Limit = parsed
		}
	}

	issues, err := svc.ListIssues(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to list issues", "error", err)
		http.Error(w, "Failed to list issues", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(issues)
}

// GiteaGetIssue returns a single issue.
// GET /integrations/gitea/repos/{id}/issues/{number}
func (h *Handler) GiteaGetIssue(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	issue, err := svc.GetIssue(r.Context(), repoID, number)
	if err != nil {
		slog.Error("failed to get issue", "error", err)
		http.Error(w, "Failed to get issue", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(issue)
}

// GiteaCreateIssue creates a new issue.
// POST /integrations/gitea/repos/{id}/issues
func (h *Handler) GiteaCreateIssue(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var opts gitea.CreateIssueOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	issue, err := svc.CreateIssue(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to create issue", "error", err)
		http.Error(w, "Failed to create issue: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(issue)
}

// GiteaEditIssue updates an issue.
// PATCH /integrations/gitea/repos/{id}/issues/{number}
func (h *Handler) GiteaEditIssue(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	var opts gitea.EditIssueOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	issue, err := svc.EditIssue(r.Context(), repoID, number, opts)
	if err != nil {
		slog.Error("failed to edit issue", "error", err)
		http.Error(w, "Failed to edit issue: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(issue)
}

// GiteaListIssueComments returns comments on an issue.
// GET /integrations/gitea/repos/{id}/issues/{number}/comments
func (h *Handler) GiteaListIssueComments(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	comments, err := svc.ListIssueComments(r.Context(), repoID, number)
	if err != nil {
		slog.Error("failed to list comments", "error", err)
		http.Error(w, "Failed to list comments", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

// GiteaCreateIssueComment creates a comment on an issue.
// POST /integrations/gitea/repos/{id}/issues/{number}/comments
func (h *Handler) GiteaCreateIssueComment(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	var input struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	comment, err := svc.CreateIssueComment(r.Context(), repoID, number, input.Body)
	if err != nil {
		slog.Error("failed to create comment", "error", err)
		http.Error(w, "Failed to create comment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(comment)
}

// GiteaDeleteIssueComment deletes a comment.
// DELETE /integrations/gitea/repos/{id}/issues/comments/{commentId}
func (h *Handler) GiteaDeleteIssueComment(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	commentID, err := strconv.ParseInt(chi.URLParam(r, "commentId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid comment ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteIssueComment(r.Context(), repoID, commentID); err != nil {
		slog.Error("failed to delete comment", "error", err)
		http.Error(w, "Failed to delete comment: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaListLabels returns labels for a repository.
// GET /integrations/gitea/repos/{id}/labels
func (h *Handler) GiteaListLabels(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	labels, err := svc.ListLabels(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list labels", "error", err)
		http.Error(w, "Failed to list labels", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(labels)
}

// GiteaListMilestones returns milestones for a repository.
// GET /integrations/gitea/repos/{id}/milestones
func (h *Handler) GiteaListMilestones(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")

	milestones, err := svc.ListMilestones(r.Context(), repoID, state)
	if err != nil {
		slog.Error("failed to list milestones", "error", err)
		http.Error(w, "Failed to list milestones", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(milestones)
}

// ============================================================================
// Tier 2: Collaborators
// ============================================================================

// GiteaListCollaborators returns collaborators for a repository.
// GET /integrations/gitea/repos/{id}/collaborators
func (h *Handler) GiteaListCollaborators(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	collaborators, err := svc.ListCollaborators(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list collaborators", "error", err)
		http.Error(w, "Failed to list collaborators", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(collaborators)
}

// GiteaAddCollaborator adds a user as a collaborator.
// PUT /integrations/gitea/repos/{id}/collaborators/{username}
func (h *Handler) GiteaAddCollaborator(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	var input struct {
		Permission string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		input.Permission = "write" // default
	}

	if err := svc.AddCollaborator(r.Context(), repoID, username, input.Permission); err != nil {
		slog.Error("failed to add collaborator", "error", err)
		http.Error(w, "Failed to add collaborator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaRemoveCollaborator removes a collaborator from a repository.
// DELETE /integrations/gitea/repos/{id}/collaborators/{username}
func (h *Handler) GiteaRemoveCollaborator(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	if err := svc.RemoveCollaborator(r.Context(), repoID, username); err != nil {
		slog.Error("failed to remove collaborator", "error", err)
		http.Error(w, "Failed to remove collaborator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaGetCollaboratorPermission returns the permission level for a collaborator.
// GET /integrations/gitea/repos/{id}/collaborators/{username}/permission
func (h *Handler) GiteaGetCollaboratorPermission(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	perms, err := svc.GetCollaboratorPermission(r.Context(), repoID, username)
	if err != nil {
		slog.Error("failed to get permission", "error", err)
		http.Error(w, "Failed to get permission", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(perms)
}

// GiteaListRepoTeams returns teams with access to a repository.
// GET /integrations/gitea/repos/{id}/teams
func (h *Handler) GiteaListRepoTeams(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	teams, err := svc.ListRepoTeams(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list teams", "error", err)
		http.Error(w, "Failed to list teams", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(teams)
}

// ============================================================================
// Helpers
// ============================================================================

// getDefaultHostID returns the default host UUID by querying the host service.
func (h *Handler) getDefaultHostID(r *http.Request) uuid.UUID {
	hosts, err := h.services.Hosts().List(r.Context())
	if err == nil && len(hosts) > 0 {
		if id, err := uuid.Parse(hosts[0].ID); err == nil {
			return id
		}
	}
	return uuid.Nil
}

// sanitizeFilename extracts the filename from a path for Content-Disposition.
func sanitizeFilename(path string) string {
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	name = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, name)
	if name == "" {
		name = "file"
	}
	return name
}

// commitAuthorName extracts author name from the nested APICommitListItem structure.
func commitAuthorName(c gitea.APICommitListItem) string {
	if c.Commit.Author != nil && c.Commit.Author.Name != "" {
		return c.Commit.Author.Name
	}
	if c.Author != nil && c.Author.Login != "" {
		return c.Author.Login
	}
	return "unknown"
}

// commitDate extracts date string from the nested APICommitListItem structure.
func commitDate(c gitea.APICommitListItem) string {
	if c.Commit.Author != nil && c.Commit.Author.Date != "" {
		// Gitea returns ISO 8601 dates, try to parse and format nicely
		if t, err := time.Parse(time.RFC3339, c.Commit.Author.Date); err == nil {
			return t.Format("2006-01-02 15:04")
		}
		return c.Commit.Author.Date
	}
	return ""
}

// ============================================================================
// Tier 3: Webhooks
// ============================================================================

// GiteaListHooks returns webhooks for a repository.
// GET /integrations/gitea/repos/{id}/hooks
func (h *Handler) GiteaListHooks(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	hooks, err := svc.ListHooks(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list hooks", "error", err)
		http.Error(w, "Failed to list webhooks", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hooks)
}

// GiteaGetHook returns a single webhook.
// GET /integrations/gitea/repos/{id}/hooks/{hookId}
func (h *Handler) GiteaGetHook(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	hookID, err := strconv.ParseInt(chi.URLParam(r, "hookId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid hook ID", http.StatusBadRequest)
		return
	}

	hook, err := svc.GetHook(r.Context(), repoID, hookID)
	if err != nil {
		slog.Error("failed to get hook", "error", err)
		http.Error(w, "Webhook not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hook)
}

// GiteaCreateHook creates a webhook.
// POST /integrations/gitea/repos/{id}/hooks
func (h *Handler) GiteaCreateHook(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var opts gitea.CreateHookOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hook, err := svc.CreateHook(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to create hook", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(hook)
}

// GiteaEditHook updates a webhook.
// PATCH /integrations/gitea/repos/{id}/hooks/{hookId}
func (h *Handler) GiteaEditHook(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	hookID, err := strconv.ParseInt(chi.URLParam(r, "hookId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid hook ID", http.StatusBadRequest)
		return
	}

	var opts gitea.EditHookOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hook, err := svc.EditHook(r.Context(), repoID, hookID, opts)
	if err != nil {
		slog.Error("failed to edit hook", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hook)
}

// GiteaDeleteHook deletes a webhook.
// DELETE /integrations/gitea/repos/{id}/hooks/{hookId}
func (h *Handler) GiteaDeleteHook(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	hookID, err := strconv.ParseInt(chi.URLParam(r, "hookId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid hook ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteHook(r.Context(), repoID, hookID); err != nil {
		slog.Error("failed to delete hook", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaTestHook tests a webhook.
// POST /integrations/gitea/repos/{id}/hooks/{hookId}/test
func (h *Handler) GiteaTestHook(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	hookID, err := strconv.ParseInt(chi.URLParam(r, "hookId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid hook ID", http.StatusBadRequest)
		return
	}

	if err := svc.TestHook(r.Context(), repoID, hookID); err != nil {
		slog.Error("failed to test hook", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Tier 3: Deploy Keys
// ============================================================================

// GiteaListDeployKeys returns deploy keys for a repository.
// GET /integrations/gitea/repos/{id}/keys
func (h *Handler) GiteaListDeployKeys(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	keys, err := svc.ListDeployKeys(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list deploy keys", "error", err)
		http.Error(w, "Failed to list deploy keys", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

// GiteaGetDeployKey returns a single deploy key.
// GET /integrations/gitea/repos/{id}/keys/{keyId}
func (h *Handler) GiteaGetDeployKey(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	keyID, err := strconv.ParseInt(chi.URLParam(r, "keyId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	key, err := svc.GetDeployKey(r.Context(), repoID, keyID)
	if err != nil {
		slog.Error("failed to get deploy key", "error", err)
		http.Error(w, "Deploy key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(key)
}

// GiteaCreateDeployKey creates a deploy key.
// POST /integrations/gitea/repos/{id}/keys
func (h *Handler) GiteaCreateDeployKey(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var opts gitea.CreateDeployKeyOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	key, err := svc.CreateDeployKey(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to create deploy key", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(key)
}

// GiteaDeleteDeployKey deletes a deploy key.
// DELETE /integrations/gitea/repos/{id}/keys/{keyId}
func (h *Handler) GiteaDeleteDeployKey(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	keyID, err := strconv.ParseInt(chi.URLParam(r, "keyId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteDeployKey(r.Context(), repoID, keyID); err != nil {
		slog.Error("failed to delete deploy key", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Tier 3: Releases
// ============================================================================

// GiteaListReleases returns releases for a repository.
// GET /integrations/gitea/repos/{id}/releases
func (h *Handler) GiteaListReleases(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	page := 1
	limit := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			limit = parsed
		}
	}

	releases, err := svc.ListReleases(r.Context(), repoID, page, limit)
	if err != nil {
		slog.Error("failed to list releases", "error", err)
		http.Error(w, "Failed to list releases", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(releases)
}

// GiteaGetRelease returns a single release.
// GET /integrations/gitea/repos/{id}/releases/{releaseId}
func (h *Handler) GiteaGetRelease(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	releaseID, err := strconv.ParseInt(chi.URLParam(r, "releaseId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid release ID", http.StatusBadRequest)
		return
	}

	release, err := svc.GetRelease(r.Context(), repoID, releaseID)
	if err != nil {
		slog.Error("failed to get release", "error", err)
		http.Error(w, "Release not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(release)
}

// GiteaGetLatestRelease returns the latest release.
// GET /integrations/gitea/repos/{id}/releases/latest
func (h *Handler) GiteaGetLatestRelease(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	release, err := svc.GetLatestRelease(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to get latest release", "error", err)
		http.Error(w, "No releases found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(release)
}

// GiteaGetReleaseByTag returns a release by tag name.
// GET /integrations/gitea/repos/{id}/releases/tags/{tag}
func (h *Handler) GiteaGetReleaseByTag(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	tag := chi.URLParam(r, "tag")
	if tag == "" {
		http.Error(w, "Tag name is required", http.StatusBadRequest)
		return
	}

	release, err := svc.GetReleaseByTag(r.Context(), repoID, tag)
	if err != nil {
		slog.Error("failed to get release by tag", "error", err)
		http.Error(w, "Release not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(release)
}

// GiteaCreateRelease creates a release.
// POST /integrations/gitea/repos/{id}/releases
func (h *Handler) GiteaCreateRelease(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	var opts gitea.CreateReleaseOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	release, err := svc.CreateRelease(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to create release", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(release)
}

// GiteaEditRelease updates a release.
// PATCH /integrations/gitea/repos/{id}/releases/{releaseId}
func (h *Handler) GiteaEditRelease(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	releaseID, err := strconv.ParseInt(chi.URLParam(r, "releaseId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid release ID", http.StatusBadRequest)
		return
	}

	var opts gitea.EditReleaseOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	release, err := svc.EditRelease(r.Context(), repoID, releaseID, opts)
	if err != nil {
		slog.Error("failed to edit release", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(release)
}

// GiteaDeleteRelease deletes a release.
// DELETE /integrations/gitea/repos/{id}/releases/{releaseId}
func (h *Handler) GiteaDeleteRelease(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	releaseID, err := strconv.ParseInt(chi.URLParam(r, "releaseId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid release ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteRelease(r.Context(), repoID, releaseID); err != nil {
		slog.Error("failed to delete release", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaListReleaseAssets returns assets for a release.
// GET /integrations/gitea/repos/{id}/releases/{releaseId}/assets
func (h *Handler) GiteaListReleaseAssets(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	releaseID, err := strconv.ParseInt(chi.URLParam(r, "releaseId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid release ID", http.StatusBadRequest)
		return
	}

	assets, err := svc.ListReleaseAssets(r.Context(), repoID, releaseID)
	if err != nil {
		slog.Error("failed to list release assets", "error", err)
		http.Error(w, "Failed to list assets", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// GiteaDeleteReleaseAsset deletes a release asset.
// DELETE /integrations/gitea/repos/{id}/releases/{releaseId}/assets/{assetId}
func (h *Handler) GiteaDeleteReleaseAsset(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	releaseID, err := strconv.ParseInt(chi.URLParam(r, "releaseId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid release ID", http.StatusBadRequest)
		return
	}

	assetID, err := strconv.ParseInt(chi.URLParam(r, "assetId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid asset ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteReleaseAsset(r.Context(), repoID, releaseID, assetID); err != nil {
		slog.Error("failed to delete release asset", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Tier 3: Actions / CI Status
// ============================================================================

// GiteaListWorkflows returns workflows for a repository.
// GET /integrations/gitea/repos/{id}/actions/workflows
func (h *Handler) GiteaListWorkflows(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	workflows, err := svc.ListWorkflows(r.Context(), repoID)
	if err != nil {
		slog.Error("failed to list workflows", "error", err)
		http.Error(w, "Failed to list workflows", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(workflows)
}

// GiteaListActionRuns returns workflow runs for a repository.
// GET /integrations/gitea/repos/{id}/actions/runs
func (h *Handler) GiteaListActionRuns(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	opts := gitea.ActionRunListOptions{
		Branch: r.URL.Query().Get("branch"),
		Event:  r.URL.Query().Get("event"),
		Status: r.URL.Query().Get("status"),
		Actor:  r.URL.Query().Get("actor"),
		Page:   1,
		Limit:  20,
	}
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			opts.Page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			opts.Limit = parsed
		}
	}

	runs, err := svc.ListActionRuns(r.Context(), repoID, opts)
	if err != nil {
		slog.Error("failed to list action runs", "error", err)
		http.Error(w, "Failed to list workflow runs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runs)
}

// GiteaGetActionRun returns a single workflow run.
// GET /integrations/gitea/repos/{id}/actions/runs/{runId}
func (h *Handler) GiteaGetActionRun(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	run, err := svc.GetActionRun(r.Context(), repoID, runID)
	if err != nil {
		slog.Error("failed to get action run", "error", err)
		http.Error(w, "Workflow run not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(run)
}

// GiteaListActionJobs returns jobs for a workflow run.
// GET /integrations/gitea/repos/{id}/actions/runs/{runId}/jobs
func (h *Handler) GiteaListActionJobs(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	jobs, err := svc.ListActionJobs(r.Context(), repoID, runID)
	if err != nil {
		slog.Error("failed to list action jobs", "error", err)
		http.Error(w, "Failed to list jobs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

// GiteaGetActionJobLogs returns logs for a job.
// GET /integrations/gitea/repos/{id}/actions/jobs/{jobId}/logs
func (h *Handler) GiteaGetActionJobLogs(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	jobID, err := strconv.ParseInt(chi.URLParam(r, "jobId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid job ID", http.StatusBadRequest)
		return
	}

	logs, err := svc.GetActionJobLogs(r.Context(), repoID, jobID)
	if err != nil {
		slog.Error("failed to get job logs", "error", err)
		http.Error(w, "Failed to get logs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(logs)
}

// GiteaCancelActionRun cancels a workflow run.
// POST /integrations/gitea/repos/{id}/actions/runs/{runId}/cancel
func (h *Handler) GiteaCancelActionRun(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	if err := svc.CancelActionRun(r.Context(), repoID, runID); err != nil {
		slog.Error("failed to cancel action run", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaRerunActionRun reruns a workflow run.
// POST /integrations/gitea/repos/{id}/actions/runs/{runId}/rerun
func (h *Handler) GiteaRerunActionRun(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	if err := svc.RerunActionRun(r.Context(), repoID, runID); err != nil {
		slog.Error("failed to rerun action run", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GiteaGetCombinedStatus returns the combined status for a commit.
// GET /integrations/gitea/repos/{id}/commits/{sha}/status
func (h *Handler) GiteaGetCombinedStatus(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	sha := chi.URLParam(r, "sha")
	if sha == "" {
		http.Error(w, "Commit SHA is required", http.StatusBadRequest)
		return
	}

	status, err := svc.GetCombinedStatus(r.Context(), repoID, sha)
	if err != nil {
		slog.Error("failed to get combined status", "error", err)
		http.Error(w, "Failed to get status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// GiteaListCommitStatuses returns statuses for a commit.
// GET /integrations/gitea/repos/{id}/commits/{sha}/statuses
func (h *Handler) GiteaListCommitStatuses(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	sha := chi.URLParam(r, "sha")
	if sha == "" {
		http.Error(w, "Commit SHA is required", http.StatusBadRequest)
		return
	}

	page := 1
	limit := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			limit = parsed
		}
	}

	statuses, err := svc.ListCommitStatuses(r.Context(), repoID, sha, page, limit)
	if err != nil {
		slog.Error("failed to list commit statuses", "error", err)
		http.Error(w, "Failed to list statuses", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

// GiteaCreateCommitStatus creates a status for a commit.
// POST /integrations/gitea/repos/{id}/statuses/{sha}
func (h *Handler) GiteaCreateCommitStatus(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	repoIDStr := chi.URLParam(r, "id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}

	sha := chi.URLParam(r, "sha")
	if sha == "" {
		http.Error(w, "Commit SHA is required", http.StatusBadRequest)
		return
	}

	var opts gitea.CreateStatusOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	status, err := svc.CreateCommitStatus(r.Context(), repoID, sha, opts)
	if err != nil {
		slog.Error("failed to create commit status", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(status)
}
