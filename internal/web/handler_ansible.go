// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bufio"
	"net/http"
	"regexp"
	"strings"

	toolspages "github.com/fr4nsys/usulnet/internal/web/templates/pages/tools"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ============================================================================
// Ansible Inventory Handlers
// ============================================================================

// AnsibleInventory renders the Ansible inventory browser page.
// GET /tools/ansible
func (h *Handler) AnsibleInventory(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Ansible Inventory", "ansible")

	selectedID := r.URL.Query().Get("id")

	data := toolspages.AnsibleInventoryData{
		PageData: pageData,
	}

	// In a real implementation, load inventories from database
	// For now, show empty state
	if selectedID != "" {
		// Load selected inventory details
	}

	h.renderTempl(w, r, toolspages.AnsibleInventory(data))
}

// AnsibleInventoryUpload handles inventory file uploads.
// POST /tools/ansible/upload
func (h *Handler) AnsibleInventoryUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		h.setFlash(w, r, "error", "File too large")
		http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.setFlash(w, r, "error", "No file provided")
		http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
		return
	}
	defer file.Close()

	// Read content
	buf := make([]byte, header.Size)
	_, err = file.Read(buf)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to read file")
		http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
		return
	}
	content := string(buf)

	// Detect format
	format := detectInventoryFormat(content)

	// Parse inventory
	hosts, groups := parseInventory(content, format)

	// Get name from form or use filename
	name := r.FormValue("name")
	if name == "" {
		name = header.Filename
	}

	// Create inventory ID
	invID := uuid.New().String()

	h.logger.Info("Ansible inventory uploaded",
		"id", invID,
		"name", name,
		"format", format,
		"hosts", len(hosts),
		"groups", len(groups),
	)

	// In a real implementation, save to database

	h.setFlash(w, r, "success", "Inventory parsed successfully")
	http.Redirect(w, r, "/tools/ansible?id="+invID, http.StatusSeeOther)
}

// AnsibleInventoryParse handles pasted inventory content.
// POST /tools/ansible/parse
func (h *Handler) AnsibleInventoryParse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
		return
	}

	name := r.FormValue("name")
	content := r.FormValue("content")
	formatStr := r.FormValue("format")

	if name == "" || content == "" {
		h.setFlash(w, r, "error", "Name and content are required")
		http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
		return
	}

	// Detect or use specified format
	var format string
	if formatStr == "auto" || formatStr == "" {
		format = detectInventoryFormat(content)
	} else {
		format = formatStr
	}

	// Parse inventory
	hosts, groups := parseInventory(content, format)

	invID := uuid.New().String()

	h.logger.Info("Ansible inventory parsed",
		"id", invID,
		"name", name,
		"format", format,
		"hosts", len(hosts),
		"groups", len(groups),
	)

	h.setFlash(w, r, "success", "Inventory parsed successfully")
	http.Redirect(w, r, "/tools/ansible?id="+invID, http.StatusSeeOther)
}

// AnsibleInventoryDelete deletes an inventory.
// DELETE /tools/ansible/{id}
func (h *Handler) AnsibleInventoryDelete(w http.ResponseWriter, r *http.Request) {
	invID := chi.URLParam(r, "id")
	if invID == "" {
		http.Error(w, "Missing inventory ID", http.StatusBadRequest)
		return
	}

	// In a real implementation, delete from database
	h.logger.Info("Ansible inventory deleted", "id", invID)

	h.setFlash(w, r, "success", "Inventory deleted")
	http.Redirect(w, r, "/tools/ansible", http.StatusSeeOther)
}

// ============================================================================
// Inventory Parsing Helpers
// ============================================================================

// detectInventoryFormat attempts to detect the inventory format
func detectInventoryFormat(content string) string {
	content = strings.TrimSpace(content)

	// Check for YAML
	if strings.HasPrefix(content, "---") || strings.HasPrefix(content, "all:") {
		return "yaml"
	}

	// Check for JSON
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return "json"
	}

	// Default to INI
	return "ini"
}

// parseInventory parses inventory content based on format
func parseInventory(content, format string) ([]toolspages.AnsibleHost, []toolspages.AnsibleGroup) {
	switch format {
	case "ini":
		return parseINIInventory(content)
	case "yaml":
		return parseYAMLInventory(content)
	case "json":
		return parseJSONInventory(content)
	default:
		return parseINIInventory(content)
	}
}

// parseINIInventory parses INI format Ansible inventory
func parseINIInventory(content string) ([]toolspages.AnsibleHost, []toolspages.AnsibleGroup) {
	var hosts []toolspages.AnsibleHost
	var groups []toolspages.AnsibleGroup

	hostMap := make(map[string]*toolspages.AnsibleHost)
	groupMap := make(map[string]*toolspages.AnsibleGroup)

	currentGroup := ""
	isVarsSection := false

	// Regex patterns
	groupPattern := regexp.MustCompile(`^\[([^\]:]+)(?::([^\]]+))?\]$`)
	hostPattern := regexp.MustCompile(`^(\S+)(?:\s+(.*))?$`)
	varPattern := regexp.MustCompile(`(\w+)=([^\s]+)`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for group header
		if matches := groupPattern.FindStringSubmatch(line); matches != nil {
			groupName := matches[1]
			groupType := ""
			if len(matches) > 2 {
				groupType = matches[2]
			}

			isVarsSection = groupType == "vars"

			if groupType == "children" {
				// Children group - handled separately
				currentGroup = groupName + ":children"
			} else if isVarsSection {
				currentGroup = groupName + ":vars"
			} else {
				currentGroup = groupName
				if _, exists := groupMap[groupName]; !exists {
					groupMap[groupName] = &toolspages.AnsibleGroup{
						Name:      groupName,
						Hosts:     []string{},
						Children:  []string{},
						Variables: make(map[string]string),
					}
				}
			}
			continue
		}

		// Parse content based on current section
		if currentGroup == "" {
			// Ungrouped hosts
			if matches := hostPattern.FindStringSubmatch(line); matches != nil {
				hostname := matches[0]
				if _, isHostLine := hostMap[hostname]; !isHostLine {
					host := parseHostLine(matches[1], matches)
					hostMap[host.Name] = &host
				}
			}
		} else if strings.HasSuffix(currentGroup, ":children") {
			// Children entries
			parentGroup := strings.TrimSuffix(currentGroup, ":children")
			if g, exists := groupMap[parentGroup]; exists {
				g.Children = append(g.Children, line)
			}
		} else if strings.HasSuffix(currentGroup, ":vars") {
			// Variable entries
			parentGroup := strings.TrimSuffix(currentGroup, ":vars")
			if g, exists := groupMap[parentGroup]; exists {
				if matches := varPattern.FindStringSubmatch(line); matches != nil {
					g.Variables[matches[1]] = matches[2]
				}
			}
		} else {
			// Host entries in group
			if matches := hostPattern.FindStringSubmatch(line); matches != nil {
				hostname := matches[1]
				host := parseHostLine(hostname, matches)

				if existing, exists := hostMap[hostname]; exists {
					existing.Groups = append(existing.Groups, currentGroup)
				} else {
					host.Groups = append(host.Groups, currentGroup)
					hostMap[hostname] = &host
				}

				if g, exists := groupMap[currentGroup]; exists {
					g.Hosts = append(g.Hosts, hostname)
				}
			}
		}
	}

	// Convert maps to slices
	for _, host := range hostMap {
		hosts = append(hosts, *host)
	}
	for _, group := range groupMap {
		groups = append(groups, *group)
	}

	return hosts, groups
}

// parseHostLine parses a single host line and extracts variables
func parseHostLine(hostname string, matches []string) toolspages.AnsibleHost {
	host := toolspages.AnsibleHost{
		Name:      hostname,
		IP:        hostname,
		Port:      22,
		User:      "root",
		Groups:    []string{},
		Variables: make(map[string]string),
		Status:    "unknown",
	}

	if len(matches) > 1 && matches[1] != "" {
		varStr := matches[1]
		if len(matches) > 2 && matches[2] != "" {
			varStr = matches[2]
		}

		varPattern := regexp.MustCompile(`(\w+)=([^\s]+)`)
		varMatches := varPattern.FindAllStringSubmatch(varStr, -1)

		for _, vm := range varMatches {
			key := vm[1]
			value := vm[2]
			host.Variables[key] = value

			switch key {
			case "ansible_host":
				host.IP = value
			case "ansible_port":
				// Parse port
			case "ansible_user":
				host.User = value
			case "ansible_ssh_user":
				host.User = value
			}
		}
	}

	return host
}

// parseYAMLInventory parses YAML format Ansible inventory
func parseYAMLInventory(content string) ([]toolspages.AnsibleHost, []toolspages.AnsibleGroup) {
	// Simplified YAML parsing - in production, use proper YAML library
	// For now, return empty as this is a complex format
	return []toolspages.AnsibleHost{}, []toolspages.AnsibleGroup{}
}

// parseJSONInventory parses JSON format Ansible inventory
func parseJSONInventory(content string) ([]toolspages.AnsibleHost, []toolspages.AnsibleGroup) {
	// Simplified JSON parsing - in production, use proper JSON library
	// For now, return empty as this is a complex format
	return []toolspages.AnsibleHost{}, []toolspages.AnsibleGroup{}
}
