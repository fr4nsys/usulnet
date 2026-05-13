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
	Icon        string         `json:"icon"`       // FontAwesome class
	IconColor   string         `json:"icon_color"` // Tailwind color class
	Category    string         `json:"category"`
	Version     string         `json:"version"`
	Website     string         `json:"website"`
	Source      string         `json:"source"` // GitHub URL
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

	// Gitea: append PostgreSQL service and DB environment when DB_TYPE=postgres
	if app.Slug == "gitea" && values["DB_TYPE"] == "postgres" {
		stackName := values["STACK_NAME"]
		if stackName == "" {
			stackName = "gitea"
		}
		dbPasswd := values["DB_PASSWD"]

		// Inject DB connection environment into the gitea service
		dbEnvBlock := fmt.Sprintf(`      - GITEA__database__HOST=%s-db:5432
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD=%s`, stackName, dbPasswd)

		// Add depends_on and DB env vars to the gitea service
		result = strings.Replace(result,
			"      - GITEA__server__SSH_LISTEN_PORT=22",
			"      - GITEA__server__SSH_LISTEN_PORT=22\n"+dbEnvBlock,
			1)

		// Add depends_on before volumes section
		dependsOnBlock := fmt.Sprintf(`    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    container_name: %s-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: gitea
      POSTGRES_PASSWORD: "%s"
      POSTGRES_DB: gitea
    volumes:
      - gitea_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U gitea -d gitea"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

`, stackName, dbPasswd)

		result = strings.Replace(result, "\nvolumes:\n", "\n"+dependsOnBlock+"volumes:\n", 1)

		// Add gitea_db volume
		result = strings.Replace(result,
			"  gitea_data:\n    driver: local\n",
			"  gitea_data:\n    driver: local\n  gitea_db:\n    driver: local\n",
			1)
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

	// Gitea: DB_PASSWD is required when using PostgreSQL
	if app.Slug == "gitea" && values["DB_TYPE"] == "postgres" && values["DB_PASSWD"] == "" {
		errors = append(errors, "'DB Password' is required when using PostgreSQL")
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
	catalogJitsiMeet(),
	catalogMatrix(),
	catalogOnlyOffice(),
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
      - minio_data:/data
    command: server /data --console-address ":9001"
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
      - GITEA__server__SSH_PORT={{SSH_PORT}}
      - GITEA__server__SSH_LISTEN_PORT=22
    volumes:
      - gitea_data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro

volumes:
  gitea_data:
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

func catalogJitsiMeet() CatalogApp {
	return CatalogApp{
		Slug:        "jitsi-meet",
		Name:        "Jitsi Meet",
		Description: "Self-hosted video conferencing. Encrypted, open-source, no account required for guests.",
		Icon:        "fa-video",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Communication",
		Version:     "stable-9location9",
		Website:     "https://jitsi.org",
		Source:      "https://github.com/jitsi/docker-jitsi-meet",
		Notes:       "After deployment, access the web interface to create or join meetings. No accounts are needed by default — anyone with the URL can join. Enable authentication in the settings to require login.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "jitsi",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "PUBLIC_URL",
				Label:       "Public URL",
				Description: "Public URL where Jitsi will be accessible (e.g. https://meet.example.com)",
				Type:        FieldText,
				Default:     "",
				Required:    true,
				Placeholder: "https://meet.example.com",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for the web interface",
				Type:        FieldNumber,
				Default:     "8000",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS access",
				Type:        FieldNumber,
				Default:     "8443",
				Required:    true,
			},
			{
				Key:         "JVB_PORT",
				Label:       "JVB Port (UDP)",
				Description: "UDP port for video bridge media traffic",
				Type:        FieldNumber,
				Default:     "10000",
				Required:    true,
			},
			{
				Key:         "TIMEZONE",
				Label:       "Timezone",
				Description: "Container timezone",
				Type:        FieldText,
				Default:     "Europe/Madrid",
				Required:    true,
				Placeholder: "Europe/Madrid",
			},
			{
				Key:         "ENABLE_AUTH",
				Label:       "Enable Authentication",
				Description: "Require login to create rooms",
				Type:        FieldSelect,
				Default:     "0",
				Required:    true,
				Options:     []string{"0", "1"},
			},
		},
		ComposeTPL: `services:
  web:
    image: jitsi/web:stable-9location9
    container_name: {{STACK_NAME}}-web
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
    environment:
      - PUBLIC_URL={{PUBLIC_URL}}
      - TZ={{TIMEZONE}}
      - ENABLE_AUTH={{ENABLE_AUTH}}
      - ENABLE_GUESTS=1
      - ENABLE_XMPP_WEBSOCKET=1
    volumes:
      - jitsi_web_config:/config
      - jitsi_web_crontabs:/var/spool/cron/crontabs
      - jitsi_transcripts:/usr/share/jitsi-meet/transcripts
    networks:
      - jitsi

  prosody:
    image: jitsi/prosody:stable-9location9
    container_name: {{STACK_NAME}}-prosody
    restart: unless-stopped
    expose:
      - "5222"
      - "5347"
      - "5280"
    environment:
      - PUBLIC_URL={{PUBLIC_URL}}
      - TZ={{TIMEZONE}}
      - ENABLE_AUTH={{ENABLE_AUTH}}
      - ENABLE_GUESTS=1
      - ENABLE_XMPP_WEBSOCKET=1
    volumes:
      - jitsi_prosody_config:/config
      - jitsi_prosody_plugins:/prosody-plugins-custom
    networks:
      - jitsi

  jicofo:
    image: jitsi/jicofo:stable-9location9
    container_name: {{STACK_NAME}}-jicofo
    restart: unless-stopped
    environment:
      - TZ={{TIMEZONE}}
    volumes:
      - jitsi_jicofo_config:/config
    depends_on:
      - prosody
    networks:
      - jitsi

  jvb:
    image: jitsi/jvb:stable-9location9
    container_name: {{STACK_NAME}}-jvb
    restart: unless-stopped
    ports:
      - "{{JVB_PORT}}:10000/udp"
    environment:
      - TZ={{TIMEZONE}}
      - JVB_PORT={{JVB_PORT}}
    volumes:
      - jitsi_jvb_config:/config
    depends_on:
      - prosody
    networks:
      - jitsi

networks:
  jitsi:
    driver: bridge

volumes:
  jitsi_web_config:
    driver: local
  jitsi_web_crontabs:
    driver: local
  jitsi_transcripts:
    driver: local
  jitsi_prosody_config:
    driver: local
  jitsi_prosody_plugins:
    driver: local
  jitsi_jicofo_config:
    driver: local
  jitsi_jvb_config:
    driver: local
`,
	}
}

func catalogMatrix() CatalogApp {
	return CatalogApp{
		Slug:        "matrix",
		Name:        "Matrix (Synapse)",
		Description: "Decentralized, encrypted communication server. Supports chat, VoIP, and bridging to other platforms.",
		Icon:        "fa-comments",
		IconColor:   "text-emerald-400 bg-emerald-500/10",
		Category:    "Communication",
		Version:     "latest",
		Website:     "https://matrix.org",
		Source:      "https://github.com/element-hq/synapse",
		Notes:       "After deployment, register your first admin user with: docker exec -it <stack>-synapse register_new_matrix_user -c /data/homeserver.yaml -a. Connect using Element Web at the configured port, or use any Matrix client pointing to your server URL.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "matrix",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "SERVER_NAME",
				Label:       "Server Name",
				Description: "Matrix server name / domain (e.g. example.com)",
				Type:        FieldText,
				Default:     "",
				Required:    true,
				Placeholder: "example.com",
			},
			{
				Key:         "SYNAPSE_PORT",
				Label:       "Synapse Port",
				Description: "Port for the Synapse API",
				Type:        FieldNumber,
				Default:     "8008",
				Required:    true,
			},
			{
				Key:         "ELEMENT_PORT",
				Label:       "Element Web Port",
				Description: "Port for the Element web client",
				Type:        FieldNumber,
				Default:     "8009",
				Required:    true,
			},
			{
				Key:         "ENABLE_REGISTRATION",
				Label:       "Open Registration",
				Description: "Allow anyone to register an account",
				Type:        FieldSelect,
				Default:     "no",
				Required:    true,
				Options:     []string{"no", "yes"},
			},
			{
				Key:         "DB_PASSWORD",
				Label:       "Database Password",
				Description: "Password for the PostgreSQL database",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
		},
		ComposeTPL: `services:
  synapse:
    image: matrixdotorg/synapse:latest
    container_name: {{STACK_NAME}}-synapse
    restart: unless-stopped
    ports:
      - "{{SYNAPSE_PORT}}:8008"
    environment:
      - SYNAPSE_SERVER_NAME={{SERVER_NAME}}
      - SYNAPSE_REPORT_STATS=no
      - SYNAPSE_NO_TLS=1
      - SYNAPSE_ENABLE_REGISTRATION={{ENABLE_REGISTRATION}}
      - SYNAPSE_DATABASE=psycopg2
      - SYNAPSE_POSTGRES_HOST={{STACK_NAME}}-db
      - SYNAPSE_POSTGRES_PORT=5432
      - SYNAPSE_POSTGRES_DB=synapse
      - SYNAPSE_POSTGRES_USER=synapse
      - SYNAPSE_POSTGRES_PASSWORD={{DB_PASSWORD}}
    volumes:
      - synapse_data:/data
    depends_on:
      db:
        condition: service_healthy
    networks:
      - matrix

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: synapse
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: synapse
      POSTGRES_INITDB_ARGS: "--encoding=UTF-8 --lc-collate=C --lc-ctype=C"
    volumes:
      - synapse_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synapse -d synapse"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - matrix

  element:
    image: vectorim/element-web:latest
    container_name: {{STACK_NAME}}-element
    restart: unless-stopped
    ports:
      - "{{ELEMENT_PORT}}:80"
    depends_on:
      - synapse
    networks:
      - matrix

networks:
  matrix:
    driver: bridge

volumes:
  synapse_data:
    driver: local
  synapse_db:
    driver: local
`,
	}
}

func catalogOnlyOffice() CatalogApp {
	return CatalogApp{
		Slug:        "onlyoffice",
		Name:        "OnlyOffice",
		Description: "Self-hosted office suite. Document, spreadsheet, and presentation editor with real-time collaboration.",
		Icon:        "fa-file-word",
		IconColor:   "text-orange-400 bg-orange-500/10",
		Category:    "Productivity",
		Version:     "latest",
		Website:     "https://www.onlyoffice.com",
		Source:      "https://github.com/ONLYOFFICE/DocumentServer",
		Notes:       "After deployment, the Document Server is available at the configured port. Integrate it with Nextcloud, ownCloud, or any other platform that supports ONLYOFFICE. Use the JWT secret to authenticate connections from your integrations.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "onlyoffice",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for the Document Server web interface",
				Type:        FieldNumber,
				Default:     "8080",
				Required:    true,
			},
			{
				Key:         "JWT_SECRET",
				Label:       "JWT Secret",
				Description: "Secret key for authenticating integration requests",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure secret",
			},
			{
				Key:         "DB_PASSWORD",
				Label:       "Database Password",
				Description: "Password for the PostgreSQL database",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
		},
		ComposeTPL: `services:
  documentserver:
    image: onlyoffice/documentserver:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
    environment:
      - JWT_ENABLED=true
      - JWT_SECRET={{JWT_SECRET}}
      - DB_TYPE=postgres
      - DB_HOST={{STACK_NAME}}-db
      - DB_PORT=5432
      - DB_NAME=onlyoffice
      - DB_USER=onlyoffice
      - DB_PWD={{DB_PASSWORD}}
      - AMQP_URI=amqp://guest:guest@{{STACK_NAME}}-rabbitmq
    volumes:
      - onlyoffice_data:/var/www/onlyoffice/Data
      - onlyoffice_logs:/var/log/onlyoffice
    depends_on:
      db:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    networks:
      - onlyoffice

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: onlyoffice
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: onlyoffice
    volumes:
      - onlyoffice_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U onlyoffice -d onlyoffice"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - onlyoffice

  rabbitmq:
    image: rabbitmq:3-alpine
    container_name: {{STACK_NAME}}-rabbitmq
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 30s
    networks:
      - onlyoffice

networks:
  onlyoffice:
    driver: bridge

volumes:
  onlyoffice_data:
    driver: local
  onlyoffice_logs:
    driver: local
  onlyoffice_db:
    driver: local
`,
	}
}
