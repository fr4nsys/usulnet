// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// =============================================================================
// BindForm covers the happy path: a fully populated form decodes into
// the struct with every Go kind we support exercised at least once.
// =============================================================================

type bindFormHappy struct {
	Name        string   `form:"name" validate:"required,min=1"`
	Description string   `form:"description"`
	Count       int      `form:"count" validate:"gte=0"`
	Threshold   float64  `form:"threshold"`
	IsActive    bool     `form:"is_active"`
	Tags        []string `form:"tags"`
}

func TestBindForm_HappyPath(t *testing.T) {
	values := url.Values{
		"name":        {"  policy-1  "},
		"description": {"a description"},
		"count":       {"42"},
		"threshold":   {"3.14"},
		"is_active":   {"on"},
		"tags":        {"a", "b", "c"},
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst bindFormHappy
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected empty message, got %q", msg)
	}

	want := bindFormHappy{
		Name:        "policy-1",
		Description: "a description",
		Count:       42,
		Threshold:   3.14,
		IsActive:    true,
		Tags:        []string{"a", "b", "c"},
	}
	if !reflect.DeepEqual(dst, want) {
		t.Errorf("decode mismatch:\n  got  %+v\n  want %+v", dst, want)
	}
}

// =============================================================================
// BindForm surfaces validation errors as a sorted, semicolon-joined
// message — the exact format flash uses.
// =============================================================================

type bindFormValidate struct {
	Name  string `form:"name" validate:"required"`
	Email string `form:"email" validate:"required,email"`
}

func TestBindForm_ValidationError(t *testing.T) {
	values := url.Values{"name": {""}, "email": {"not-an-email"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst bindFormValidate
	msg, fields := BindFormFields(req, &dst)
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	if !strings.Contains(msg, "email") || !strings.Contains(msg, "name") {
		t.Errorf("flash msg should mention both fields, got %q", msg)
	}
	// Sorted order: email < name → email error first.
	if !strings.HasPrefix(msg, "email ") {
		t.Errorf("flash msg should be sorted (email first), got %q", msg)
	}
	if len(fields) != 2 {
		t.Errorf("expected 2 field errors, got %d: %v", len(fields), fields)
	}
	if _, ok := fields["name"]; !ok {
		t.Errorf("field map should contain 'name', got %v", fields)
	}
}

// =============================================================================
// Numeric and bool conversions — boundary cases that decodeForm
// must reject with a useful per-field message.
// =============================================================================

type bindFormNumeric struct {
	Count int `form:"count"`
}

func TestBindForm_NumericRejection(t *testing.T) {
	values := url.Values{"count": {"not-a-number"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst bindFormNumeric
	msg := BindForm(req, &dst)
	if msg == "" {
		t.Fatal("expected error message for non-numeric input")
	}
	if !strings.Contains(msg, "count") {
		t.Errorf("error should mention field name, got %q", msg)
	}
}

func TestBindForm_BoolConversion(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"on", true},
		{"true", true},
		{"1", true},
		{"yes", true},
		{"", false},
		{"off", false},
		{"false", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			values := url.Values{"is_active": {tc.raw}}
			req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			var dst struct {
				IsActive bool `form:"is_active"`
			}
			if msg := BindForm(req, &dst); msg != "" {
				t.Fatalf("expected success, got %q", msg)
			}
			if dst.IsActive != tc.want {
				t.Errorf("raw %q: got %v, want %v", tc.raw, dst.IsActive, tc.want)
			}
		})
	}
}

// =============================================================================
// Tag handling: `-`, omitempty, default snake_case derivation.
// =============================================================================

func TestBindForm_TagOptions(t *testing.T) {
	type tagged struct {
		Public  string `form:"public"`
		Private string `form:"-"`
		// PostalCode has no explicit tag → defaults to "postal_code".
		PostalCode string
	}
	values := url.Values{
		"public":      {"yes"},
		"private":     {"should-be-skipped"},
		"postal_code": {"08001"},
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst tagged
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected success, got %q", msg)
	}
	if dst.Public != "yes" {
		t.Errorf("public mismatch: %q", dst.Public)
	}
	if dst.Private != "" {
		t.Errorf("private should be skipped by form:'-', got %q", dst.Private)
	}
	if dst.PostalCode != "08001" {
		t.Errorf("default snake_case: %q", dst.PostalCode)
	}
}

// =============================================================================
// Pointer fields — present vs absent semantics. A nil pointer after
// decoding means the form key was absent, distinguishing "not sent"
// from "sent empty".
// =============================================================================

func TestBindForm_PointerAbsence(t *testing.T) {
	type withPtr struct {
		Optional *string `form:"optional"`
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst withPtr
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected success, got %q", msg)
	}
	if dst.Optional != nil {
		t.Errorf("pointer should stay nil for absent key, got %q", *dst.Optional)
	}
}

func TestBindForm_PointerPresent(t *testing.T) {
	type withPtr struct {
		Optional *string `form:"optional"`
	}
	values := url.Values{"optional": {"x"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst withPtr
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected success, got %q", msg)
	}
	if dst.Optional == nil {
		t.Fatal("pointer should be allocated for present key")
	}
	if *dst.Optional != "x" {
		t.Errorf("value mismatch: %q", *dst.Optional)
	}
}

// =============================================================================
// Misuse: a nil dst or a non-pointer must surface a clear error
// rather than panic — handlers depend on this for safety.
// =============================================================================

func TestBindForm_RejectsNilOrNonPointer(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// nil pointer
	var nilPtr *bindFormHappy
	if msg := BindForm(req, nilPtr); msg == "" {
		t.Errorf("nil dst should produce error")
	}

	// not a pointer
	var notPtr bindFormHappy
	if msg := BindForm(req, notPtr); msg == "" {
		t.Errorf("non-pointer dst should produce error")
	}
}

// =============================================================================
// Slice fields collect every value for the key (multi-select).
// =============================================================================

func TestBindForm_SliceMultiValue(t *testing.T) {
	type multi struct {
		Roles []string `form:"roles"`
	}
	values := url.Values{"roles": {"admin", "viewer", "operator"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst multi
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected success, got %q", msg)
	}
	want := []string{"admin", "viewer", "operator"}
	if !reflect.DeepEqual(dst.Roles, want) {
		t.Errorf("multi-value decode mismatch: got %v, want %v", dst.Roles, want)
	}
}

// =============================================================================
// Embedded struct decoding — proxyHostUpdateForm pattern (the
// update DTO embeds the create DTO to inherit its fields). The
// inner struct's fields must populate from form keys named for
// the embedded type's tags, not for the embedded type itself.
// =============================================================================

type embeddedInner struct {
	Domain      string `form:"domain" validate:"required"`
	ForwardPort int    `form:"forward_port"`
}

type embeddedOuter struct {
	embeddedInner
	Enabled bool `form:"enabled"`
}

func TestBindForm_EmbeddedStruct(t *testing.T) {
	values := url.Values{
		"domain":       {"example.com"},
		"forward_port": {"8080"},
		"enabled":      {"on"},
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var dst embeddedOuter
	if msg := BindForm(req, &dst); msg != "" {
		t.Fatalf("expected success, got %q", msg)
	}
	if dst.Domain != "example.com" || dst.ForwardPort != 8080 || !dst.Enabled {
		t.Errorf("embedded decode mismatch: %+v", dst)
	}
}

// =============================================================================
// toSnakeCase regression — the default field-name derivation must
// remain stable; handlers rely on the conversion matching the HTML
// form-key convention already in tree.
// =============================================================================

func TestToSnakeCase(t *testing.T) {
	cases := map[string]string{
		"Name":          "name",
		"PostalCode":    "postal_code",
		"IsEnabled":     "is_enabled",
		"HTTPSPort":     "h_t_t_p_s_port", // brittle on acronyms — see comment in toSnakeCase
		"already_snake": "already_snake",
	}
	for in, want := range cases {
		if got := toSnakeCase(in); got != want {
			t.Errorf("toSnakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}
