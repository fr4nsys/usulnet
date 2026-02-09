// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package notification provides the notification service for USULNET.
// Department L: Notifications
package notification

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// TemplateEngine renders notification messages using templates.
type TemplateEngine struct {
	templates map[channels.NotificationType]*NotificationTemplate
	funcMap   template.FuncMap
}

// NotificationTemplate holds templates for a notification type.
type NotificationTemplate struct {
	Title     *template.Template
	Body      *template.Template
	BodyPlain *template.Template
}

// TemplateData is the data passed to notification templates.
type TemplateData struct {
	// Notification metadata
	Type      channels.NotificationType
	Priority  channels.Priority
	Timestamp time.Time

	// Core data (varies by notification type)
	Data map[string]interface{}

	// Helpers
	Env string // Environment (production, staging, dev)
}

// NewTemplateEngine creates a new template engine with default templates.
func NewTemplateEngine() *TemplateEngine {
	engine := &TemplateEngine{
		templates: make(map[channels.NotificationType]*NotificationTemplate),
		funcMap: template.FuncMap{
			"upper":    strings.ToUpper,
			"lower":    strings.ToLower,
			"title":    strings.Title,
			"trim":     strings.TrimSpace,
			"truncate": truncate,
			"join":     strings.Join,
			"default":  defaultValue,
			"formatTime": func(t time.Time) string {
				return t.Format("2006-01-02 15:04:05 MST")
			},
			"formatDuration": formatDuration,
			"humanBytes":     humanBytes,
		},
	}

	engine.registerDefaultTemplates()
	return engine
}

// Render renders a notification message from templates.
func (e *TemplateEngine) Render(msg Message) (channels.RenderedMessage, error) {
	tmpl, exists := e.templates[msg.Type]
	if !exists {
		// Use generic template
		tmpl = e.templates["_default"]
	}

	data := TemplateData{
		Type:      msg.Type,
		Priority:  msg.Priority,
		Timestamp: time.Now(),
		Data:      msg.Data,
	}

	rendered := channels.RenderedMessage{
		Type:      msg.Type,
		Priority:  msg.Priority,
		Timestamp: data.Timestamp,
		Data:      msg.Data,
		Color:     msg.Type.DefaultColor(),
	}

	// Render title
	if tmpl.Title != nil {
		var buf bytes.Buffer
		if err := tmpl.Title.Execute(&buf, data); err != nil {
			return rendered, fmt.Errorf("failed to render title: %w", err)
		}
		rendered.Title = strings.TrimSpace(buf.String())
	} else {
		rendered.Title = msg.Title
	}

	// Render body (HTML/Markdown)
	if tmpl.Body != nil {
		var buf bytes.Buffer
		if err := tmpl.Body.Execute(&buf, data); err != nil {
			return rendered, fmt.Errorf("failed to render body: %w", err)
		}
		rendered.Body = strings.TrimSpace(buf.String())
	} else {
		rendered.Body = msg.Body
	}

	// Render plain text body
	if tmpl.BodyPlain != nil {
		var buf bytes.Buffer
		if err := tmpl.BodyPlain.Execute(&buf, data); err != nil {
			return rendered, fmt.Errorf("failed to render plain body: %w", err)
		}
		rendered.BodyPlain = strings.TrimSpace(buf.String())
	} else {
		// Strip HTML tags for plain text
		rendered.BodyPlain = stripHTMLTags(rendered.Body)
	}

	// Override with message-provided values if present
	if msg.Title != "" {
		rendered.Title = msg.Title
	}
	if msg.Body != "" {
		rendered.Body = msg.Body
	}

	return rendered, nil
}

// RegisterTemplate registers a custom template for a notification type.
func (e *TemplateEngine) RegisterTemplate(notifType channels.NotificationType, title, body, bodyPlain string) error {
	tmpl := &NotificationTemplate{}

	var err error
	if title != "" {
		tmpl.Title, err = template.New("title").Funcs(e.funcMap).Parse(title)
		if err != nil {
			return fmt.Errorf("invalid title template: %w", err)
		}
	}

	if body != "" {
		tmpl.Body, err = template.New("body").Funcs(e.funcMap).Parse(body)
		if err != nil {
			return fmt.Errorf("invalid body template: %w", err)
		}
	}

	if bodyPlain != "" {
		tmpl.BodyPlain, err = template.New("bodyPlain").Funcs(e.funcMap).Parse(bodyPlain)
		if err != nil {
			return fmt.Errorf("invalid plain body template: %w", err)
		}
	}

	e.templates[notifType] = tmpl
	return nil
}

// registerDefaultTemplates sets up the built-in templates.
func (e *TemplateEngine) registerDefaultTemplates() {
	// Default fallback template
	e.templates["_default"] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`{{.Type.Category | title}}: {{.Data.message | default "Notification"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`{{.Data.message | default "A notification was triggered."}}{{if .Data.details}}

**Details:** {{.Data.details}}{{end}}`,
		)),
		BodyPlain: must(template.New("bodyPlain").Funcs(e.funcMap).Parse(
			`{{.Data.message | default "A notification was triggered."}}{{if .Data.details}}

Details: {{.Data.details}}{{end}}`,
		)),
	}

	// Security Alert
	e.templates[channels.TypeSecurityAlert] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Security Alert: {{.Data.title | default "Issue Detected"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`🔒 **Security Issue Detected**

{{.Data.message}}

{{if .Data.container}}**Container:** {{.Data.container}}{{end}}
{{if .Data.severity}}**Severity:** {{.Data.severity | upper}}{{end}}
{{if .Data.recommendation}}**Recommendation:** {{.Data.recommendation}}{{end}}`,
		)),
	}

	// CVE Detected
	e.templates[channels.TypeCVEDetected] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`CVE Detected: {{.Data.cve_id | default "Unknown CVE"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`🛡️ **Vulnerability Found**

**CVE ID:** {{.Data.cve_id}}
**Severity:** {{.Data.severity | upper}}
{{if .Data.container}}**Container:** {{.Data.container}}{{end}}
{{if .Data.image}}**Image:** {{.Data.image}}{{end}}
{{if .Data.package}}**Package:** {{.Data.package}}{{end}}

{{.Data.description | truncate 500}}

{{if .Data.fix_version}}**Fix Available:** Upgrade to {{.Data.fix_version}}{{end}}`,
		)),
	}

	// Update Available
	e.templates[channels.TypeUpdateAvailable] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Update Available: {{.Data.container | default "Container"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`📦 **New Version Available**

**Container:** {{.Data.container}}
**Current:** {{.Data.current_version}}
**Available:** {{.Data.new_version}}

{{if .Data.changelog}}**What's New:**
{{.Data.changelog | truncate 1000}}{{end}}`,
		)),
	}

	// Update Completed
	e.templates[channels.TypeUpdateCompleted] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Update Completed: {{.Data.container}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`✅ **Update Successful**

**Container:** {{.Data.container}}
**Previous:** {{.Data.from_version}}
**Current:** {{.Data.to_version}}
{{if .Data.duration}}**Duration:** {{.Data.duration | formatDuration}}{{end}}`,
		)),
	}

	// Update Failed
	e.templates[channels.TypeUpdateFailed] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Update Failed: {{.Data.container}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`❌ **Update Failed**

**Container:** {{.Data.container}}
**Attempted:** {{.Data.from_version}} → {{.Data.to_version}}
**Error:** {{.Data.error}}

{{if .Data.rolled_back}}The container has been rolled back to the previous version.{{end}}`,
		)),
	}

	// Backup Completed
	e.templates[channels.TypeBackupCompleted] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Backup Completed: {{.Data.container | default "System"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`💾 **Backup Successful**

{{if .Data.container}}**Container:** {{.Data.container}}{{end}}
**Size:** {{.Data.size | humanBytes}}
**Location:** {{.Data.path}}
{{if .Data.duration}}**Duration:** {{.Data.duration | formatDuration}}{{end}}`,
		)),
	}

	// Backup Failed
	e.templates[channels.TypeBackupFailed] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Backup Failed: {{.Data.container | default "System"}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`❌ **Backup Failed**

{{if .Data.container}}**Container:** {{.Data.container}}{{end}}
**Error:** {{.Data.error}}

Please investigate and retry the backup manually.`,
		)),
	}

	// Container Down
	e.templates[channels.TypeContainerDown] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Container Down: {{.Data.container}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`🔴 **Container Stopped**

**Container:** {{.Data.container}}
**Image:** {{.Data.image}}
{{if .Data.exit_code}}**Exit Code:** {{.Data.exit_code}}{{end}}
{{if .Data.error}}**Error:** {{.Data.error}}{{end}}
{{if .Data.last_log}}**Last Log:**
` + "```" + `
{{.Data.last_log | truncate 500}}
` + "```" + `{{end}}`,
		)),
	}

	// Host Offline
	e.templates[channels.TypeHostOffline] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Host Offline: {{.Data.host}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`🔴 **Host Unreachable**

**Host:** {{.Data.host}}
**Last Seen:** {{.Data.last_seen | formatTime}}
{{if .Data.containers}}**Containers Affected:** {{.Data.containers}}{{end}}

The host agent is not responding. Please check connectivity.`,
		)),
	}

	// Health Check Failed
	e.templates[channels.TypeHealthCheckFailed] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`Health Check Failed: {{.Data.container}}`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`⚠️ **Health Check Failed**

**Container:** {{.Data.container}}
**Check:** {{.Data.check}}
{{if .Data.consecutive_failures}}**Consecutive Failures:** {{.Data.consecutive_failures}}{{end}}
{{if .Data.output}}**Output:** {{.Data.output | truncate 300}}{{end}}`,
		)),
	}

	// Test Message
	e.templates[channels.TypeTestMessage] = &NotificationTemplate{
		Title: must(template.New("title").Funcs(e.funcMap).Parse(
			`USULNET Test Notification`,
		)),
		Body: must(template.New("body").Funcs(e.funcMap).Parse(
			`🧪 **Test Notification**

This is a test message from USULNET to verify your notification configuration is working correctly.

If you received this message, your notification channel is properly configured!`,
		)),
	}
}

// Helper functions

func must(t *template.Template, err error) *template.Template {
	if err != nil {
		panic(err)
	}
	return t
}

func truncate(length int, s string) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func defaultValue(def, val interface{}) interface{} {
	if val == nil || val == "" {
		return def
	}
	return val
}

func formatDuration(d interface{}) string {
	var dur time.Duration

	switch v := d.(type) {
	case time.Duration:
		dur = v
	case int64:
		dur = time.Duration(v) * time.Second
	case float64:
		dur = time.Duration(v) * time.Second
	case int:
		dur = time.Duration(v) * time.Second
	default:
		return fmt.Sprintf("%v", d)
	}

	if dur < time.Minute {
		return fmt.Sprintf("%.0fs", dur.Seconds())
	}
	if dur < time.Hour {
		return fmt.Sprintf("%.0fm %.0fs", dur.Minutes(), float64(int(dur.Seconds())%60))
	}
	return fmt.Sprintf("%.0fh %.0fm", dur.Hours(), float64(int(dur.Minutes())%60))
}

func humanBytes(b interface{}) string {
	var bytes int64

	switch v := b.(type) {
	case int64:
		bytes = v
	case int:
		bytes = int64(v)
	case float64:
		bytes = int64(v)
	default:
		return fmt.Sprintf("%v", b)
	}

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

func stripHTMLTags(s string) string {
	var result strings.Builder
	inTag := false

	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}
