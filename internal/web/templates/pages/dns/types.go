// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dns groups the templ templates that render the DNS provider
// pages of the usulnet web UI. The templates work off the view-model
// types declared here so the web handler can adapt service models
// once and then pass them through unchanged.
package dns

import "github.com/fr4nsys/usulnet/internal/web/templates/layouts"

// ProviderView is the row shape of the provider list page.
type ProviderView struct {
	ID           string
	Name         string
	ProviderKind string
	KindLabel    string
	Description  string
	Enabled      bool
	RecordCount  int
	CreatedAt    string
}

// CapabilityView mirrors dns.Capabilities for templ consumption.
type CapabilityView struct {
	Kind             string
	DisplayName      string
	Description      string
	Records          []CapabilityRecord
	CredentialFields []CredentialFieldView
	ConfigFields     []ConfigFieldView
}

// CapabilityRecord is a per-RR-type row in the capability matrix.
type CapabilityRecord struct {
	Type      string
	Read      bool
	Write     bool
	UpdateTTL bool
}

// CredentialFieldView documents one field of the credential JSON blob.
type CredentialFieldView struct {
	Key         string
	Label       string
	Required    bool
	Secret      bool
	Description string
}

// ConfigFieldView documents one knob in the non-secret config map.
type ConfigFieldView struct {
	Key         string
	Label       string
	Type        string
	Description string
	Default     string
}

// RecordView is the row shape of the records page.
type RecordView struct {
	ID         string
	ProviderID string
	Name       string
	Type       string
	Content    string
	TTL        int
	ManagedBy  string
	IsManual   bool
	CreatedAt  string
}

// OrderView is the row shape of the ACME order list page.
type OrderView struct {
	ID             string
	Domain         string
	ProviderID     string
	ProviderName   string
	State          string
	StateLabel     string
	StateClass     string
	ErrorMsg       string
	ChallengeFQDN  string
	ChallengeValue string
	PropChecks     int
	LastCheck      string
	CompletedAt    string
	CreatedAt      string
}

// AuditEntryView is the row shape of an audit log entry.
type AuditEntryView struct {
	When         string
	UserID       string
	Action       string
	ResourceType string
	ResourceName string
	Details      string
}

// ============================================================================
// Page data envelopes
// ============================================================================

// ProviderListData is passed to the provider list page.
type ProviderListData struct {
	PageData     layouts.PageData
	Providers    []ProviderView
	Capabilities []CapabilityView
}

// ProviderFormData backs the new/edit forms.
type ProviderFormData struct {
	PageData     layouts.PageData
	IsEdit       bool
	Provider     ProviderView
	Capabilities []CapabilityView
	Selected     CapabilityView // capability for the currently chosen kind
	ConfigJSON   string         // pretty-printed for the textarea
	Error        string
}

// ProviderDetailData powers the per-provider page.
type ProviderDetailData struct {
	PageData layouts.PageData
	Provider ProviderView
	Records  []RecordView
	Selected CapabilityView
}

// RecordNewData backs the "add record" form.
type RecordNewData struct {
	PageData layouts.PageData
	Provider ProviderView
	Selected CapabilityView
	Error    string
}

// OrderListData powers the ACME orders page.
type OrderListData struct {
	PageData layouts.PageData
	Orders   []OrderView
}

// OrderDetailData powers a single ACME order page.
type OrderDetailData struct {
	PageData layouts.PageData
	Order    OrderView
	Audit    []AuditEntryView
}

// AuditPageData powers the audit page.
type AuditPageData struct {
	PageData layouts.PageData
	Entries  []AuditEntryView
	Total    int
	Page     int
	PageSize int
}

// CapabilityPageData powers the supported-providers matrix page.
type CapabilityPageData struct {
	PageData     layouts.PageData
	Capabilities []CapabilityView
}

// EmptyData is used when the service is not configured.
type EmptyData struct {
	PageData layouts.PageData
	Message  string
}
