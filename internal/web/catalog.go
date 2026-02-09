// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"strings"
)

// CatalogFieldType defines the type of a configuration field.
type CatalogFieldType string

const (
	FieldText     CatalogFieldType = "text"
	FieldPassword CatalogFieldType = "password"
	FieldNumber   CatalogFieldType = "number"
	FieldSelect   CatalogFieldType = "select"
	FieldCheckbox CatalogFieldType = "checkbox"
)

// CatalogField represents a configurable field in an app template.
type CatalogField struct {
	Key         string           `json:"key"`
	Label       string           `json:"label"`
	Description string           `json:"description"`
	Type        CatalogFieldType `json:"type"`
	Default     string           `json:"default"`
	Required    bool             `json:"required"`
	Options     []string         `json:"options,omitempty"` // For select type
	Placeholder string           `json:"placeholder,omitempty"`
	Pattern     string           `json:"pattern,omitempty"` // HTML input pattern
}

// CatalogApp represents an application template in the catalog.
type CatalogApp struct {
	Slug        string         `json:"slug"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon"`        // FontAwesome class
	IconColor   string         `json:"icon_color"`   // Tailwind color class
	Category    string         `json:"category"`
	Version     string         `json:"version"`
	Website     string         `json:"website"`
	Source      string         `json:"source"`       // GitHub URL
	Fields      []CatalogField `json:"fields"`
	ComposeTPL  string         `json:"-"` // Go template for docker-compose.yml
	Notes       string         `json:"notes,omitempty"`
}

// RenderCompose renders the docker-compose template with the given field values.
// Uses simple {{KEY}} placeholder replacement (not Go templates, to avoid complexity).
func (app *CatalogApp) RenderCompose(values map[string]string) string {
	result := app.ComposeTPL
	for _, field := range app.Fields {
		val, ok := values[field.Key]
		if !ok || val == "" {
			val = field.Default
		}
		result = strings.ReplaceAll(result, "{{"+field.Key+"}}", val)
	}
	return result
}

// Validate checks that all required fields have values.
func (app *CatalogApp) Validate(values map[string]string) []string {
	var errors []string
	for _, f := range app.Fields {
		if f.Required {
			v := values[f.Key]
			if v == "" && f.Default == "" {
				errors = append(errors, fmt.Sprintf("'%s' is required", f.Label))
			}
		}
	}
	return errors
}

// GetDefaultValues returns a map of field keys to their default values.
func (app *CatalogApp) GetDefaultValues() map[string]string {
	vals := make(map[string]string, len(app.Fields))
	for _, f := range app.Fields {
		vals[f.Key] = f.Default
	}
	return vals
}

// ============================================================================
// Catalog Registry
// ============================================================================

// catalogApps holds all available app templates.
var catalogApps = []CatalogApp{
	catalogMinIO(),
	catalogGitea(),
	catalogDDNSUpdater(),
	catalogNginxProxyManager(),
	catalogCaddy(),
	catalogCodeServer(),
}

// GetCatalogApps returns all available catalog apps.
func GetCatalogApps() []CatalogApp {
	return catalogApps
}

// GetCatalogApp returns a catalog app by slug, or nil if not found.
func GetCatalogApp(slug string) *CatalogApp {
	for i := range catalogApps {
		if catalogApps[i].Slug == slug {
			return &catalogApps[i]
		}
	}
	return nil
}

// GetCatalogCategories returns unique categories.
func GetCatalogCategories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, app := range catalogApps {
		if !seen[app.Category] {
			seen[app.Category] = true
			cats = append(cats, app.Category)
		}
	}
	return cats
}

// ============================================================================
// App Definitions
// ============================================================================

func catalogMinIO() CatalogApp {
	return CatalogApp{
		Slug:        "minio",
		Name:        "MinIO",
		Description: "S3-compatible object storage. High performance, Kubernetes-native.",
		Icon:        "fa-database",
		IconColor:   "text-red-400 bg-red-500/10",
		Category:    "Storage",
		Version:     "latest",
		Website:     "https://min.io",
		Source:      "https://github.com/minio/minio",
		Notes:       "After first startup, access the web console to create buckets and manage users. Default credentials are the ones you set here.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "minio",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
				Placeholder: "minio",
			},
			{
				Key:         "MINIO_ROOT_USER",
				Label:       "Root User",
				Description: "MinIO admin user",
				Type:        FieldText,
				Default:     "minioadmin",
				Required:    true,
			},
			{
				Key:         "MINIO_ROOT_PASSWORD",
				Label:       "Root Password",
				Description: "Admin password (minimum 8 characters)",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
			{
				Key:         "API_PORT",
				Label:       "API Port (S3)",
				Description: "Port for the S3-compatible API",
				Type:        FieldNumber,
				Default:     "9000",
				Required:    true,
			},
			{
				Key:         "CONSOLE_PORT",
				Label:       "Web Console Port",
				Description: "Port for the admin web interface",
				Type:        FieldNumber,
				Default:     "9001",
				Required:    true,
			},
			{
				Key:         "DATA_PATH",
				Label:       "Data Path",
				Description: "Host directory for data storage",
				Type:        FieldText,
				Default:     "./minio-data",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  minio:
    image: minio/minio:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{API_PORT}}:9000"
      - "{{CONSOLE_PORT}}:9001"
    environment:
      MINIO_ROOT_USER: "{{MINIO_ROOT_USER}}"
      MINIO_ROOT_PASSWORD: "{{MINIO_ROOT_PASSWORD}}"
    volumes:
      - minio_data:{{DATA_PATH}}
    command: server {{DATA_PATH}} --console-address ":9001"
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  minio_data:
    driver: local
`,
	}
}

func catalogGitea() CatalogApp {
	return CatalogApp{
		Slug:        "gitea",
		Name:        "Gitea",
		Description: "Lightweight self-hosted Git server. Simple alternative to GitLab/GitHub.",
		Icon:        "fa-code-branch",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Development",
		Version:     "latest",
		Website:     "https://gitea.io",
		Source:      "https://github.com/go-gitea/gitea",
		Notes:       "On first access, Gitea will show an installation wizard. If using SQLite, no external DB is needed. For PostgreSQL, make sure the database container is running first.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "gitea",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port to access the web interface",
				Type:        FieldNumber,
				Default:     "3000",
				Required:    true,
			},
			{
				Key:         "SSH_PORT",
				Label:       "SSH Port",
				Description: "Port for Git operations over SSH",
				Type:        FieldNumber,
				Default:     "2222",
				Required:    true,
			},
			{
				Key:         "DB_TYPE",
				Label:       "Database",
				Description: "Database engine to use",
				Type:        FieldSelect,
				Default:     "sqlite3",
				Required:    true,
				Options:     []string{"sqlite3", "postgres"},
			},
			{
				Key:         "DB_PASSWD",
				Label:       "DB Password (PostgreSQL only)",
				Description: "PostgreSQL password. Ignored if using SQLite.",
				Type:        FieldPassword,
				Default:     "",
				Required:    false,
				Placeholder: "only if using postgres",
			},
			{
				Key:         "DATA_PATH",
				Label:       "Data Path",
				Description: "Host directory for repositories and configuration",
				Type:        FieldText,
				Default:     "./gitea-data",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  gitea:
    image: gitea/gitea:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:3000"
      - "{{SSH_PORT}}:22"
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE={{DB_TYPE}}
      - GITEA__database__HOST={{STACK_NAME}}-db:5432
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD={{DB_PASSWD}}
      - GITEA__server__SSH_PORT={{SSH_PORT}}
      - GITEA__server__SSH_LISTEN_PORT=22
    volumes:
      - gitea_data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: gitea
      POSTGRES_PASSWORD: "{{DB_PASSWD}}"
      POSTGRES_DB: gitea
    volumes:
      - gitea_db:/var/lib/postgresql/data

volumes:
  gitea_data:
    driver: local
  gitea_db:
    driver: local
`,
	}
}

func catalogDDNSUpdater() CatalogApp {
	return CatalogApp{
		Slug:        "ddns-updater",
		Name:        "DDNS Updater",
		Description: "Dynamic DNS updater. Supports Cloudflare, Namecheap, DuckDNS, OVH, and many more.",
		Icon:        "fa-globe",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://github.com/qdm12/ddns-updater",
		Source:      "https://github.com/qdm12/ddns-updater",
		Notes:       "After deployment, access the web interface to check update status. Edit the config.json file in the data path to configure your DNS providers.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "ddns-updater",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "WEB_PORT",
				Label:       "Web Port",
				Description: "Port for the status web interface",
				Type:        FieldNumber,
				Default:     "8000",
				Required:    true,
			},
			{
				Key:         "UPDATE_PERIOD",
				Label:       "Update Period",
				Description: "Interval between checks (e.g. 5m, 30m, 1h)",
				Type:        FieldText,
				Default:     "5m",
				Required:    true,
				Placeholder: "5m",
			},
			{
				Key:         "DATA_PATH",
				Label:       "Data Path",
				Description: "Host directory for configuration and data",
				Type:        FieldText,
				Default:     "./ddns-data",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  ddns-updater:
    image: qmcgaw/ddns-updater:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:8000"
    environment:
      - PERIOD={{UPDATE_PERIOD}}
      - TZ=Europe/Madrid
    volumes:
      - ddns_data:/updater/data

volumes:
  ddns_data:
    driver: local
`,
	}
}

func catalogNginxProxyManager() CatalogApp {
	return CatalogApp{
		Slug:        "nginx-proxy-manager",
		Name:        "Nginx Proxy Manager",
		Description: "Reverse proxy management UI with free SSL certificates. Easy to use, with Let's Encrypt support.",
		Icon:        "fa-shield-alt",
		IconColor:   "text-orange-400 bg-orange-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://nginxproxymanager.com",
		Source:      "https://github.com/NginxProxyManager/nginx-proxy-manager",
		Notes:       "Default login: admin@example.com / changeme. You will be prompted to change your email and password on first login.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "npm",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for HTTP traffic",
				Type:        FieldNumber,
				Default:     "80",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS traffic",
				Type:        FieldNumber,
				Default:     "443",
				Required:    true,
			},
			{
				Key:         "ADMIN_PORT",
				Label:       "Admin UI Port",
				Description: "Port for the admin web interface",
				Type:        FieldNumber,
				Default:     "81",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
      - "{{ADMIN_PORT}}:81"
    volumes:
      - npm_data:/data
      - npm_letsencrypt:/etc/letsencrypt
    healthcheck:
      test: ["CMD", "/usr/bin/check-health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  npm_data:
    driver: local
  npm_letsencrypt:
    driver: local
`,
	}
}

func catalogCaddy() CatalogApp {
	return CatalogApp{
		Slug:        "caddy",
		Name:        "Caddy",
		Description: "Powerful, enterprise-ready web server with automatic HTTPS. Zero-config TLS certificates.",
		Icon:        "fa-lock",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://caddyserver.com",
		Source:      "https://github.com/caddyserver/caddy",
		Notes:       "Edit the Caddyfile in the data volume to configure your sites. Caddy automatically provisions TLS certificates via Let's Encrypt.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "caddy",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for HTTP traffic",
				Type:        FieldNumber,
				Default:     "80",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS traffic",
				Type:        FieldNumber,
				Default:     "443",
				Required:    true,
			},
			{
				Key:         "ADMIN_PORT",
				Label:       "Admin API Port",
				Description: "Port for the Caddy admin API (0 to disable)",
				Type:        FieldNumber,
				Default:     "2019",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  caddy:
    image: caddy:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
      - "{{ADMIN_PORT}}:2019"
    volumes:
      - caddy_data:/data
      - caddy_config:/config
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
    environment:
      - CADDY_ADMIN=0.0.0.0:2019

volumes:
  caddy_data:
    driver: local
  caddy_config:
    driver: local
`,
	}
}

func catalogCodeServer() CatalogApp {
	return CatalogApp{
		Slug:        "code-server",
		Name:        "Code Server",
		Description: "VS Code in the browser. Full IDE experience accessible from any device with a web browser.",
		Icon:        "fa-laptop-code",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Development",
		Version:     "latest",
		Website:     "https://coder.com",
		Source:      "https://github.com/coder/code-server",
		Notes:       "Access the web interface with the password you configure. Your workspace is persisted in the data volume.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "code-server",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "WEB_PORT",
				Label:       "Web Port",
				Description: "Port to access the IDE",
				Type:        FieldNumber,
				Default:     "8443",
				Required:    true,
			},
			{
				Key:         "PASSWORD",
				Label:       "Password",
				Description: "Password to access code-server",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
			{
				Key:         "SUDO_PASSWORD",
				Label:       "Sudo Password",
				Description: "Password for sudo inside the container (optional)",
				Type:        FieldPassword,
				Default:     "",
				Required:    false,
				Placeholder: "optional",
			},
		},
		ComposeTPL: `services:
  code-server:
    image: lscr.io/linuxserver/code-server:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:8443"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Madrid
      - PASSWORD={{PASSWORD}}
      - SUDO_PASSWORD={{SUDO_PASSWORD}}
    volumes:
      - code_data:/config

volumes:
  code_data:
    driver: local
`,
	}
}
