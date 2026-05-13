// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package spiderfoot

import (
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// EventMapping classifies a SpiderFoot event type into the
// engine-agnostic (category, severity, confidence) triple used by
// recon.EngineEvent. confidence is the default the adapter assigns
// when SpiderFoot itself does not surface one in the event row; if
// SpiderFoot reports a per-event confidence value, the engine
// preserves that instead.
type EventMapping struct {
	Category   string
	Severity   recon.Severity
	Confidence int
}

// UnknownMapping is the fallback returned by MapEventType for any
// SpiderFoot event type the table does not cover.
var UnknownMapping = EventMapping{
	Category:   "unknown",
	Severity:   recon.SeverityInfo,
	Confidence: 20,
}

// eventMap covers every SpiderFoot event type emitted by the four
// built-in profiles (email-exposure-lite, domain-surface,
// username-presence, phone-public-info). Extending it is safe — new
// event types appear here, not in engine.go.
//
// Severity guidance:
//   - "info"     — public, expected metadata (DNS, gravatar presence)
//   - "low"      — public exposure of low-sensitivity info (subdomains,
//     social profiles)
//   - "medium"   — affiliated/associated assets, public usernames,
//     malicious-IP signals against affiliates
//   - "high"     — direct compromise indicators: breached emails,
//     malicious-IP signals against the target itself
//   - "critical" — credential leak with cleartext data
var eventMap = map[string]EventMapping{
	// Identity / contact
	"EMAILADDR":         {Category: "identity", Severity: recon.SeverityLow, Confidence: 80},
	"EMAILADDR_GENERIC": {Category: "identity", Severity: recon.SeverityInfo, Confidence: 60},
	"EMAIL_ADDRESS":     {Category: "identity", Severity: recon.SeverityLow, Confidence: 80},
	"USERNAME":          {Category: "identity", Severity: recon.SeverityLow, Confidence: 70},
	"HUMAN_NAME":        {Category: "identity", Severity: recon.SeverityLow, Confidence: 60},
	"PHONE_NUMBER":      {Category: "identity", Severity: recon.SeverityLow, Confidence: 70},
	"ACCOUNT_EXTERNAL_OWNED": {
		Category: "social", Severity: recon.SeverityLow, Confidence: 75,
	},
	"SOCIAL_MEDIA": {Category: "social", Severity: recon.SeverityLow, Confidence: 75},

	// Breaches / compromise
	"BREACH_DATA":             {Category: "breach", Severity: recon.SeverityHigh, Confidence: 90},
	"EMAILADDR_COMPROMISED":   {Category: "breach", Severity: recon.SeverityHigh, Confidence: 90},
	"PASSWORD_COMPROMISED":    {Category: "breach", Severity: recon.SeverityCritical, Confidence: 95},
	"HASH_COMPROMISED":        {Category: "breach", Severity: recon.SeverityCritical, Confidence: 95},
	"LEAKSITE_CONTENT":        {Category: "breach", Severity: recon.SeverityHigh, Confidence: 80},
	"LEAKSITE_URL":            {Category: "breach", Severity: recon.SeverityHigh, Confidence: 80},
	"MALICIOUS_EMAILADDR":     {Category: "reputation", Severity: recon.SeverityHigh, Confidence: 85},
	"MALICIOUS_INTERNET_NAME": {Category: "reputation", Severity: recon.SeverityHigh, Confidence: 85},
	"MALICIOUS_IPADDR":        {Category: "reputation", Severity: recon.SeverityHigh, Confidence: 85},

	// Domain / DNS surface
	"DOMAIN_NAME":              {Category: "domain", Severity: recon.SeverityInfo, Confidence: 95},
	"DOMAIN_NAME_PARENT":       {Category: "domain", Severity: recon.SeverityInfo, Confidence: 95},
	"INTERNET_NAME":            {Category: "domain", Severity: recon.SeverityLow, Confidence: 90},
	"INTERNET_NAME_UNRESOLVED": {Category: "domain", Severity: recon.SeverityInfo, Confidence: 70},
	"CO_HOSTED_SITE":           {Category: "domain", Severity: recon.SeverityLow, Confidence: 70},
	"DNS_TEXT":                 {Category: "dns", Severity: recon.SeverityInfo, Confidence: 80},
	"DNS_SPF":                  {Category: "dns", Severity: recon.SeverityInfo, Confidence: 80},

	// Affiliates (out-of-target but adjacent)
	"AFFILIATE_DOMAIN_NAME":   {Category: "affiliate", Severity: recon.SeverityLow, Confidence: 60},
	"AFFILIATE_INTERNET_NAME": {Category: "affiliate", Severity: recon.SeverityLow, Confidence: 60},
	"AFFILIATE_IPADDR":        {Category: "affiliate", Severity: recon.SeverityInfo, Confidence: 60},
	"AFFILIATE_EMAILADDR":     {Category: "affiliate", Severity: recon.SeverityLow, Confidence: 60},
	"AFFILIATE_WEB_CONTENT":   {Category: "affiliate", Severity: recon.SeverityInfo, Confidence: 50},

	// Network
	"IP_ADDRESS":       {Category: "network", Severity: recon.SeverityInfo, Confidence: 90},
	"IPV6_ADDRESS":     {Category: "network", Severity: recon.SeverityInfo, Confidence: 90},
	"NETBLOCK_OWNER":   {Category: "network", Severity: recon.SeverityInfo, Confidence: 80},
	"NETBLOCK_MEMBER":  {Category: "network", Severity: recon.SeverityInfo, Confidence: 80},
	"BGP_AS_OWNER":     {Category: "network", Severity: recon.SeverityInfo, Confidence: 80},
	"BGP_AS_MEMBER":    {Category: "network", Severity: recon.SeverityInfo, Confidence: 80},
	"PROVIDER_DNS":     {Category: "network", Severity: recon.SeverityInfo, Confidence: 70},
	"PROVIDER_HOSTING": {Category: "network", Severity: recon.SeverityInfo, Confidence: 70},
	"PROVIDER_MAIL":    {Category: "network", Severity: recon.SeverityInfo, Confidence: 70},
	"GEOINFO":          {Category: "network", Severity: recon.SeverityInfo, Confidence: 60},
	"PHYSICAL_ADDRESS": {Category: "network", Severity: recon.SeverityLow, Confidence: 60},
	"PHYSICAL_COORDINATES": {
		Category: "network", Severity: recon.SeverityLow, Confidence: 60,
	},

	// Certificates / web
	"SSL_CERTIFICATE_ISSUED":  {Category: "certificate", Severity: recon.SeverityInfo, Confidence: 90},
	"SSL_CERTIFICATE_ISSUER":  {Category: "certificate", Severity: recon.SeverityInfo, Confidence: 90},
	"SSL_CERTIFICATE_EXPIRED": {Category: "certificate", Severity: recon.SeverityMedium, Confidence: 90},
	"WEB_ANALYTICS_ID":        {Category: "web", Severity: recon.SeverityInfo, Confidence: 70},
	"URL_FORM":                {Category: "web", Severity: recon.SeverityInfo, Confidence: 60},
	"URL_STATIC":              {Category: "web", Severity: recon.SeverityInfo, Confidence: 60},
	"LINKED_URL_INTERNAL":     {Category: "web", Severity: recon.SeverityInfo, Confidence: 60},
	"LINKED_URL_EXTERNAL":     {Category: "web", Severity: recon.SeverityInfo, Confidence: 60},

	// Raw / passthrough (kept low-confidence so the UI doesn't show
	// them by default but the data is preserved).
	"RAW_RIR_DATA": {Category: "raw", Severity: recon.SeverityInfo, Confidence: 40},
	"RAW_DNS_RECORDS": {
		Category: "raw", Severity: recon.SeverityInfo, Confidence: 40,
	},
	"SEARCH_ENGINE_WEB_CONTENT": {Category: "raw", Severity: recon.SeverityInfo, Confidence: 40},
	"TARGET_WEB_CONTENT":        {Category: "raw", Severity: recon.SeverityInfo, Confidence: 40},

	// Scan lifecycle markers SpiderFoot emits as pseudo-events. We
	// classify them as "system" so callers can filter them out
	// before persistence.
	"ROOT": {Category: "system", Severity: recon.SeverityInfo, Confidence: 100},
}

// MapEventType returns the configured EventMapping for a SpiderFoot
// event type. Unknown types fall back to UnknownMapping.
func MapEventType(eventType string) EventMapping {
	if m, ok := eventMap[eventType]; ok {
		return m
	}
	return UnknownMapping
}

// KnownEventTypes returns the set of SpiderFoot event types the
// mapping table covers. The slice is freshly allocated; callers may
// sort or modify it freely. Used by tests to assert exhaustiveness.
func KnownEventTypes() []string {
	out := make([]string, 0, len(eventMap))
	for k := range eventMap {
		out = append(out, k)
	}
	return out
}
