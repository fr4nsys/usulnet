// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	editorpages "github.com/fr4nsys/usulnet/internal/web/templates/pages/editor"
)

// ============================================================================
// Editor Hub Page
// ============================================================================

// EditorHub renders the editor landing page with quick actions and connected repos.
// Works without Gitea configured - shows scratch pad options.
// GET /editor
func (h *Handler) EditorHub(w http.ResponseWriter, r *http.Request) {
	// If query params present, delegate to Monaco
	if r.URL.Query().Get("repo") != "" {
		h.EditorMonaco(w, r)
		return
	}

	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Editor", "editor")

	data := editorpages.HubData{
		PageData: pageData,
	}

	// Fetch user's snippets
	user := GetUserFromContext(ctx)
	if user != nil && h.snippetRepo != nil {
		userID, err := uuid.Parse(user.ID)
		if err == nil {
			snippets, err := h.snippetRepo.List(ctx, userID, nil)
			if err == nil {
				for _, s := range snippets {
					data.Snippets = append(data.Snippets, editorpages.SnippetItem{
						ID:        s.ID.String(),
						Name:      s.Name,
						Path:      s.Path,
						Language:  s.Language,
						Size:      int64(s.ContentSize),
						SizeHuman: formatBytesEditor(int64(s.ContentSize)),
						UpdatedAt: s.UpdatedAt.Format("Jan 2, 2006"),
					})
				}
			}
		}
	}

	// If Gitea service is available, fetch connections
	svc := h.services.Gitea()
	if svc != nil {
		data.HasGitea = true
		conns, err := svc.ListAllConnections(ctx)
		if err == nil {
			for _, c := range conns {
				data.Connections = append(data.Connections, editorpages.HubConnection{
					ID:         c.ID.String(),
					Name:       c.Name,
					URL:        c.URL,
					Provider:   "gitea",
					Status:     string(c.Status),
					ReposCount: c.ReposCount,
				})
			}
		}
	}

	h.renderTempl(w, r, editorpages.Hub(data))
}

// formatBytesEditor formats bytes as human readable string
func formatBytesEditor(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ============================================================================
// Monaco Editor Page
// ============================================================================

// EditorMonaco renders the Monaco editor page.
// With repo param: loads file from git provider.
// Without repo param: opens scratch editor (empty file).
// GET /editor/monaco?repo={id}&file={path}&ref={branch}
// GET /editor/monaco (scratch mode)
func (h *Handler) EditorMonaco(w http.ResponseWriter, r *http.Request) {
	repoIDStr := r.URL.Query().Get("repo")
	filePath := r.URL.Query().Get("file")
	ref := r.URL.Query().Get("ref")

	// Snippet mode: load a saved snippet into the editor
	snippetIDStr := r.URL.Query().Get("snippet")
	if snippetIDStr != "" && h.snippetRepo != nil {
		user := GetUserFromContext(r.Context())
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		userID, err := uuid.Parse(user.ID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
		snippetID, err := uuid.Parse(snippetIDStr)
		if err != nil {
			http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
			return
		}
		snippet, err := h.snippetRepo.Get(r.Context(), userID, snippetID)
		if err != nil {
			h.setFlash(w, r, "error", "Snippet not found")
			http.Redirect(w, r, "/editor", http.StatusSeeOther)
			return
		}

		displayName := snippet.Name
		if snippet.Path != "" {
			displayName = snippet.Path + "/" + snippet.Name
		}

		pageData := h.prepareTemplPageData(r, "Edit: "+snippet.Name, "editor")
		pageData.FullScreen = true
		data := editorpages.MonacoData{
			PageData:    pageData,
			FilePath:    displayName,
			Language:    snippet.Language,
			Content:     snippet.Content,
			SnippetID:   snippetIDStr,
			SnippetName: snippet.Name,
		}
		h.renderTempl(w, r, editorpages.Monaco(data))
		return
	}

	// Scratch mode: no repo param, open empty editor
	if repoIDStr == "" {
		lang := "plaintext"
		if filePath != "" {
			lang = detectLanguage(filePath)
		} else {
			filePath = "scratch.txt"
		}

		pageData := h.prepareTemplPageData(r, "Scratch Editor", "editor")
		pageData.FullScreen = true // Editor needs full height
		data := editorpages.MonacoData{
			PageData: pageData,
			FilePath: filePath,
			Language: lang,
			Content:  "", // empty scratch pad
		}
		h.renderTempl(w, r, editorpages.Monaco(data))
		return
	}

	// Git mode: requires Gitea service
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	if filePath == "" {
		http.Error(w, "file parameter required", http.StatusBadRequest)
		return
	}

	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	repo, err := svc.GetRepository(ctx, repoID)
	if err != nil {
		h.setFlash(w, r, "error", "Repository not found")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	if ref == "" {
		ref = repo.DefaultBranch
	}

	// Fetch file content
	content, err := svc.GetFileContent(ctx, repoID, filePath, ref)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to read file: "+err.Error())
		http.Redirect(w, r, "/integrations/gitea/repos/"+repoIDStr+"?ref="+ref, http.StatusSeeOther)
		return
	}

	// Detect if binary
	if isBinaryContent(content) {
		h.setFlash(w, r, "error", "Cannot edit binary files in Monaco")
		http.Redirect(w, r, "/integrations/gitea/repos/"+repoIDStr+"?ref="+ref, http.StatusSeeOther)
		return
	}

	// Base64 encode for safe JS embedding
	b64Content := base64.StdEncoding.EncodeToString(content)

	lang := detectLanguage(filePath)
	pageData := h.prepareTemplPageData(r, "Edit: "+filepath.Base(filePath), "editor")
	pageData.FullScreen = true // Editor needs full height

	data := editorpages.MonacoData{
		PageData: pageData,
		RepoID:   repoIDStr,
		RepoName: repo.FullName,
		FilePath: filePath,
		Ref:      ref,
		Content:  b64Content,
		Language: lang,
		ReadOnly: repo.IsArchived,
	}
	h.renderTempl(w, r, editorpages.Monaco(data))
}

// ============================================================================
// Neovim Editor Page
// ============================================================================

// EditorNvim renders the nvim terminal page.
// With repo param: opens file from git provider.
// Without repo param: opens clean nvim session.
// GET /editor/nvim?repo={id}&file={path}&ref={branch}
// GET /editor/nvim (standalone)
func (h *Handler) EditorNvim(w http.ResponseWriter, r *http.Request) {
	repoIDStr := r.URL.Query().Get("repo")
	filePath := r.URL.Query().Get("file")
	ref := r.URL.Query().Get("ref")

	// Standalone mode: no repo param
	if repoIDStr == "" {
		lang := "plaintext"
		if filePath != "" {
			lang = detectLanguage(filePath)
		} else {
			filePath = "scratch" // Default filename for scratch mode
		}

		pageData := h.prepareTemplPageData(r, "Neovim Terminal", "editor")
		pageData.FullScreen = true // Editor needs full height
		data := editorpages.NvimData{
			PageData: pageData,
			FilePath: filePath,
			Language: lang,
		}
		h.renderTempl(w, r, editorpages.Nvim(data))
		return
	}

	// Git mode
	svc := h.services.Gitea()
	if svc == nil {
		http.Error(w, "Git integration not configured", http.StatusServiceUnavailable)
		return
	}

	if filePath == "" {
		http.Error(w, "file parameter required", http.StatusBadRequest)
		return
	}

	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		http.Error(w, "Invalid repo ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	repo, err := svc.GetRepository(ctx, repoID)
	if err != nil {
		h.setFlash(w, r, "error", "Repository not found")
		http.Redirect(w, r, "/integrations/gitea", http.StatusSeeOther)
		return
	}

	if ref == "" {
		ref = repo.DefaultBranch
	}

	lang := detectLanguage(filePath)
	pageData := h.prepareTemplPageData(r, "nvim: "+filepath.Base(filePath), "editor")
	pageData.FullScreen = true // Editor needs full height

	data := editorpages.NvimData{
		PageData: pageData,
		RepoID:   repoIDStr,
		RepoName: repo.FullName,
		FilePath: filePath,
		Ref:      ref,
		Language: lang,
	}
	h.renderTempl(w, r, editorpages.Nvim(data))
}

// ============================================================================
// Language Detection
// ============================================================================

// detectLanguage maps file extension to Monaco language ID.
func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Special filenames
	switch base {
	case "dockerfile":
		return "dockerfile"
	case "makefile", "gnumakefile":
		return "makefile"
	case "gemfile", "rakefile":
		return "ruby"
	case "vagrantfile":
		return "ruby"
	case "cmakelists.txt":
		return "cmake"
	case "docker-compose.yml", "docker-compose.yaml":
		return "yaml"
	case ".gitignore", ".dockerignore":
		return "ignore"
	case ".env", ".env.local", ".env.production":
		return "dotenv"
	case "justfile":
		return "makefile"
	}

	switch ext {
	case ".go":
		return "go"
	case ".templ":
		return "go"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".mts", ".cts":
		return "typescript"
	case ".jsx":
		return "javascript"
	case ".tsx":
		return "typescript"
	case ".html", ".htm":
		return "html"
	case ".css":
		return "css"
	case ".scss":
		return "scss"
	case ".less":
		return "less"
	case ".vue":
		return "html"
	case ".svelte":
		return "html"
	case ".json", ".jsonc":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "ini"
	case ".xml", ".svg", ".xsl":
		return "xml"
	case ".csv":
		return "plaintext"
	case ".graphql", ".gql":
		return "graphql"
	case ".proto":
		return "protobuf"
	case ".ini", ".cfg":
		return "ini"
	case ".conf", ".cnf":
		return "ini"
	case ".env":
		return "dotenv"
	case ".properties":
		return "ini"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".fish":
		return "shell"
	case ".ps1", ".psm1":
		return "powershell"
	case ".bat", ".cmd":
		return "bat"
	case ".py", ".pyw":
		return "python"
	case ".rb":
		return "ruby"
	case ".rs":
		return "rust"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".swift":
		return "swift"
	case ".cs":
		return "csharp"
	case ".php":
		return "php"
	case ".lua":
		return "lua"
	case ".r", ".rmd":
		return "r"
	case ".pl", ".pm":
		return "perl"
	case ".ex", ".exs":
		return "elixir"
	case ".erl", ".hrl":
		return "erlang"
	case ".zig":
		return "zig"
	case ".nim":
		return "nim"
	case ".dart":
		return "dart"
	case ".scala":
		return "scala"
	case ".clj", ".cljs":
		return "clojure"
	case ".hs":
		return "haskell"
	case ".md", ".markdown":
		return "markdown"
	case ".rst":
		return "restructuredtext"
	case ".tex", ".latex":
		return "latex"
	case ".sql":
		return "sql"
	case ".pgsql":
		return "pgsql"
	case ".mysql":
		return "mysql"
	case ".tf", ".tfvars":
		return "hcl"
	case ".hcl":
		return "hcl"
	case ".nix":
		return "nix"
	case ".diff", ".patch":
		return "diff"
	case ".log":
		return "log"
	case ".txt", ".text":
		return "plaintext"
	default:
		return "plaintext"
	}
}

// isBinaryContent checks if content appears to be binary (has null bytes in first 8KB).
func isBinaryContent(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	for _, b := range sample {
		if b == 0 {
			return true
		}
	}
	return false
}
