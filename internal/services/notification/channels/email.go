// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package channels provides notification channel implementations.
// Department L: Notifications
package channels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailChannel sends notifications via SMTP email.
type EmailChannel struct {
	config       EmailConfig
	htmlTemplate *template.Template
	textTemplate *template.Template
}

// EmailConfig holds email channel configuration.
type EmailConfig struct {
	// SMTP server settings
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// TLS configuration
	UseTLS      bool `json:"use_tls"`       // Use STARTTLS
	UseSSL      bool `json:"use_ssl"`       // Use implicit TLS (port 465)
	SkipVerify  bool `json:"skip_verify"`   // Skip certificate verification
	
	// Sender settings
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name,omitempty"`
	ReplyTo     string `json:"reply_to,omitempty"`

	// Recipients
	ToAddresses  []string `json:"to_addresses"`
	CCAddresses  []string `json:"cc_addresses,omitempty"`
	BCCAddresses []string `json:"bcc_addresses,omitempty"`

	// Content settings
	SubjectPrefix string `json:"subject_prefix,omitempty"` // e.g., "[USULNET]"
	SendHTML      *bool  `json:"send_html,omitempty"`      // Send HTML emails

	// Timeout in seconds
	Timeout int `json:"timeout,omitempty"`
}

// NewEmailChannel creates a new email notification channel.
func NewEmailChannel(config EmailConfig) (*EmailChannel, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if config.Port == 0 {
		// Default ports based on TLS settings
		if config.UseSSL {
			config.Port = 465
		} else if config.UseTLS {
			config.Port = 587
		} else {
			config.Port = 25
		}
	}
	if config.FromAddress == "" {
		return nil, fmt.Errorf("from address is required")
	}
	if len(config.ToAddresses) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Set defaults
	if config.FromName == "" {
		config.FromName = "USULNET"
	}
	if config.SubjectPrefix == "" {
		config.SubjectPrefix = "[USULNET]"
	}
	if config.SendHTML == nil {
		sendHTML := true
		config.SendHTML = &sendHTML
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	channel := &EmailChannel{
		config: config,
	}

	// Parse templates
	if err := channel.initTemplates(); err != nil {
		return nil, fmt.Errorf("failed to init templates: %w", err)
	}

	return channel, nil
}

// Name returns the channel identifier.
func (e *EmailChannel) Name() string {
	return "email"
}

// IsConfigured returns true if the channel has valid configuration.
func (e *EmailChannel) IsConfigured() bool {
	return e.config.Host != "" && e.config.FromAddress != "" && len(e.config.ToAddresses) > 0
}

// Send delivers a notification via email.
func (e *EmailChannel) Send(ctx context.Context, msg RenderedMessage) error {
	// Build email content
	subject := e.buildSubject(msg)
	body, contentType, err := e.buildBody(msg)
	if err != nil {
		return fmt.Errorf("failed to build email body: %w", err)
	}

	// Build message
	emailMsg := e.buildMessage(subject, body, contentType)

	// Send email
	if err := e.sendMail(ctx, emailMsg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// Test sends a test email to verify configuration.
func (e *EmailChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify email configuration.",
		BodyPlain: "This is a test notification from USULNET to verify email configuration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return e.Send(ctx, testMsg)
}

// buildSubject creates the email subject line.
func (e *EmailChannel) buildSubject(msg RenderedMessage) string {
	priorityPrefix := ""
	if msg.Priority >= PriorityCritical {
		priorityPrefix = "[CRITICAL] "
	} else if msg.Priority >= PriorityHigh {
		priorityPrefix = "[IMPORTANT] "
	}

	return fmt.Sprintf("%s %s%s", e.config.SubjectPrefix, priorityPrefix, msg.Title)
}

// buildBody creates the email body (HTML or plain text).
func (e *EmailChannel) buildBody(msg RenderedMessage) (string, string, error) {
	if *e.config.SendHTML {
		var buf bytes.Buffer
		data := map[string]interface{}{
			"Title":     msg.Title,
			"Body":      template.HTML(msg.Body), // Allow HTML in body
			"Priority":  msg.Priority.String(),
			"Type":      string(msg.Type),
			"Category":  msg.Type.Category(),
			"Timestamp": msg.Timestamp.Format("2006-01-02 15:04:05 MST"),
			"Color":     msg.Color,
			"Data":      msg.Data,
		}

		if err := e.htmlTemplate.Execute(&buf, data); err != nil {
			return "", "", err
		}

		return buf.String(), "text/html; charset=UTF-8", nil
	}

	// Plain text fallback
	return msg.BodyPlain, "text/plain; charset=UTF-8", nil
}

// buildMessage creates the MIME message.
func (e *EmailChannel) buildMessage(subject, body, contentType string) []byte {
	var buf bytes.Buffer

	// Headers
	from := e.formatAddress(e.config.FromName, e.config.FromAddress)
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(e.config.ToAddresses, ", ")))
	
	if len(e.config.CCAddresses) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(e.config.CCAddresses, ", ")))
	}
	
	if e.config.ReplyTo != "" {
		buf.WriteString(fmt.Sprintf("Reply-To: %s\r\n", e.config.ReplyTo))
	}

	// Encode subject for UTF-8
	encodedSubject := e.encodeSubject(subject)
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("X-Mailer: USULNET\r\n")
	buf.WriteString("\r\n")

	// Base64 encoded body
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	// Wrap at 76 characters per line
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}

	return buf.Bytes()
}

// sendMail sends the email via SMTP.
func (e *EmailChannel) sendMail(ctx context.Context, message []byte) error {
	addr := fmt.Sprintf("%s:%d", e.config.Host, e.config.Port)

	// Collect all recipients
	recipients := make([]string, 0, len(e.config.ToAddresses)+len(e.config.CCAddresses)+len(e.config.BCCAddresses))
	recipients = append(recipients, e.config.ToAddresses...)
	recipients = append(recipients, e.config.CCAddresses...)
	recipients = append(recipients, e.config.BCCAddresses...)

	tlsConfig := &tls.Config{
		ServerName:         e.config.Host,
		InsecureSkipVerify: e.config.SkipVerify,
	}

	var conn net.Conn
	var err error

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(e.config.Timeout) * time.Second,
	}

	if e.config.UseSSL {
		// Implicit TLS (port 465)
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, e.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// STARTTLS if configured (and not using implicit TLS)
	if e.config.UseTLS && !e.config.UseSSL {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	// Authenticate if credentials provided
	if e.config.Username != "" && e.config.Password != "" {
		auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(e.config.FromAddress); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", rcpt, err)
		}
	}

	// Send message
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to open data: %w", err)
	}

	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close data: %w", err)
	}

	return client.Quit()
}

// formatAddress formats a name/email pair.
func (e *EmailChannel) formatAddress(name, address string) string {
	if name == "" {
		return address
	}
	// Encode name if it contains non-ASCII
	if needsEncoding(name) {
		return fmt.Sprintf("=?UTF-8?B?%s?= <%s>", base64.StdEncoding.EncodeToString([]byte(name)), address)
	}
	return fmt.Sprintf("%s <%s>", name, address)
}

// encodeSubject encodes the subject for UTF-8 if needed.
func (e *EmailChannel) encodeSubject(subject string) string {
	if needsEncoding(subject) {
		return fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(subject)))
	}
	return subject
}

// needsEncoding checks if a string contains non-ASCII characters.
func needsEncoding(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// initTemplates initializes the HTML email template.
func (e *EmailChannel) initTemplates() error {
	htmlTmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f3f4f6; }
        .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .header { background: {{.Color}}; color: white; padding: 20px; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .content { padding: 20px; color: #374151; line-height: 1.6; }
        .meta { padding: 15px 20px; background: #f9fafb; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
        .meta span { margin-right: 15px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #fef3c7; color: #92400e; }
        .badge-normal { background: #dbeafe; color: #1e40af; }
        .badge-low { background: #f3f4f6; color: #4b5563; }
        .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .data-table th, .data-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        .data-table th { background: #f9fafb; font-weight: 600; font-size: 12px; color: #6b7280; text-transform: uppercase; }
        .footer { padding: 15px 20px; text-align: center; font-size: 11px; color: #9ca3af; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
        </div>
        <div class="content">
            {{.Body}}
            {{if .Data}}
            <table class="data-table">
                <thead>
                    <tr><th>Field</th><th>Value</th></tr>
                </thead>
                <tbody>
                    {{range $key, $value := .Data}}
                    <tr><td>{{$key}}</td><td>{{$value}}</td></tr>
                    {{end}}
                </tbody>
            </table>
            {{end}}
        </div>
        <div class="meta">
            <span class="badge badge-{{.Priority}}">{{.Priority}}</span>
            <span>Type: {{.Category}}</span>
            <span>{{.Timestamp}}</span>
        </div>
        <div class="footer">
            Sent by USULNET Docker Management Platform
        </div>
    </div>
</body>
</html>`

	var err error
	e.htmlTemplate, err = template.New("email").Parse(htmlTmpl)
	if err != nil {
		return err
	}

	return nil
}

// NewEmailChannelFromSettings creates an EmailChannel from generic settings map.
func NewEmailChannelFromSettings(settings map[string]interface{}) (*EmailChannel, error) {
	// Manual conversion to handle nested types
	config := EmailConfig{}

	if v, ok := settings["host"].(string); ok {
		config.Host = v
	}
	if v, ok := settings["port"].(float64); ok {
		config.Port = int(v)
	}
	if v, ok := settings["username"].(string); ok {
		config.Username = v
	}
	if v, ok := settings["password"].(string); ok {
		config.Password = v
	}
	if v, ok := settings["use_tls"].(bool); ok {
		config.UseTLS = v
	}
	if v, ok := settings["use_ssl"].(bool); ok {
		config.UseSSL = v
	}
	if v, ok := settings["skip_verify"].(bool); ok {
		config.SkipVerify = v
	}
	if v, ok := settings["from_address"].(string); ok {
		config.FromAddress = v
	}
	if v, ok := settings["from_name"].(string); ok {
		config.FromName = v
	}
	if v, ok := settings["reply_to"].(string); ok {
		config.ReplyTo = v
	}
	if v, ok := settings["to_addresses"].([]interface{}); ok {
		for _, addr := range v {
			if s, ok := addr.(string); ok {
				config.ToAddresses = append(config.ToAddresses, s)
			}
		}
	}
	if v, ok := settings["cc_addresses"].([]interface{}); ok {
		for _, addr := range v {
			if s, ok := addr.(string); ok {
				config.CCAddresses = append(config.CCAddresses, s)
			}
		}
	}
	if v, ok := settings["subject_prefix"].(string); ok {
		config.SubjectPrefix = v
	}
	if v, ok := settings["send_html"].(bool); ok {
		config.SendHTML = &v
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewEmailChannel(config)
}
