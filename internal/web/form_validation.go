// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/fr4nsys/usulnet/internal/pkg/validator"
)

// =============================================================================
// Server-side form validation — unified entry point for every POST/PUT
// handler under internal/web/.
//
// The web layer historically used a mix of inline `if x == ""` checks
// against r.FormValue and a hand-rolled error string passed to
// setFlash. That pattern duplicated boilerplate across 40+ handlers
// and let the rules for "name required" / "max length" drift apart
// between handlers (we have at least three different phrasings of the
// same error in tree).
//
// BindForm centralises the contract: a struct DTO with `form:"..."`
// + `validate:"..."` tags is the only configuration; the helper
// parses r.PostForm into it and runs validator.Validate, returning a
// single human-readable message ready for setFlash + redirect. The
// per-field error map is also exposed (BindFormFields) for handlers
// that re-render the form with field-level hints instead of a flash.
//
// The helper is intentionally minimal — no map[string]interface{}
// generic decoding, no time.Time parsing — handlers that need those
// pull the raw value via r.FormValue after BindForm has validated
// the structured fields.
// =============================================================================

// BindForm parses r.Form into dst and validates the resulting struct.
//
// dst must be a non-nil pointer to a struct. Each exported field is
// mapped from a form value by the `form:"<name>"` tag (falling back
// to a snake_case version of the field name); validation rules are
// taken from the `validate:"..."` tag and dispatched through the
// internal/pkg/validator package so the error messages stay
// consistent with the JSON API layer.
//
// Returns "" on success. On any failure (form parse error, decode
// error, validation error) returns a single human-readable message
// suitable for setFlash. Use BindFormFields when the caller needs
// the per-field error map (e.g. to re-render the form with hints
// next to each input).
func BindForm(r *http.Request, dst any) string {
	msg, _ := BindFormFields(r, dst)
	return msg
}

// BindFormFields is the field-level variant of BindForm. On a
// validation failure it returns both the flattened flash message and
// the field→message map; on a parse / decode failure only the
// message (the map is nil because the validator never ran).
//
// The field names in the returned map are the form-key names — the
// same identifiers the HTML inputs use — even when the struct does
// not carry an explicit json tag. The internal/pkg/validator package
// resolves field names from json tags and would otherwise leak the
// Go field name (PascalCase) into flash messages.
func BindFormFields(r *http.Request, dst any) (string, map[string]string) {
	if err := r.ParseForm(); err != nil {
		return "Invalid form data", nil
	}
	if err := decodeForm(r, dst); err != nil {
		return err.Error(), nil
	}
	if err := validator.Validate(dst); err != nil {
		raw := validator.GetValidationErrors(err)
		fields := translateFieldNames(dst, raw)
		return flattenFieldErrors(fields), fields
	}
	return "", nil
}

// translateFieldNames rewrites the keys of the validator's error
// map from the Go field name to the form-key name declared via
// `form:"..."` tag (or the snake_case fallback). Without this step
// flash messages would surface "Email must be a valid email
// address" instead of "email must be a valid email address" — a
// minor cosmetic mismatch that nonetheless breaks templates that
// switch on the lowercase form key to position field-level hints.
func translateFieldNames(dst any, raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return raw
	}
	val := reflect.ValueOf(dst)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return raw
	}
	typ := val.Type()
	rename := make(map[string]string, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		fld := typ.Field(i)
		if !fld.IsExported() {
			continue
		}
		name, _ := parseFormTag(fld)
		if name == "-" {
			continue
		}
		rename[fld.Name] = name
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if mapped, ok := rename[k]; ok {
			out[mapped] = v
		} else {
			out[k] = v
		}
	}
	return out
}

// flattenFieldErrors turns the per-field error map into a single
// human-readable sentence, sorted deterministically so the message
// is stable across re-renders. The format is "<field> <msg>; ..."
// — e.g. "name is required; email must be a valid email address".
func flattenFieldErrors(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "_error" {
			parts = append(parts, fields[k])
			continue
		}
		parts = append(parts, k+" "+fields[k])
	}
	return strings.Join(parts, "; ")
}

// decodeForm walks the exported fields of *dst (which must be a
// non-nil pointer to a struct) and assigns r.PostForm / r.Form
// values into them, converting per the field's Go kind. Strings are
// TrimSpace'd; bools accept "on" (HTML checkbox default), "true",
// "1", "yes", "y", or any other value as false; numerics use
// strconv. Slice-of-string fields receive every value the form key
// carries (use with multi-selects / checkbox groups).
//
// Tag conventions:
//
//	form:"name"   — override the form key (default: snake_case of field name)
//	form:"-"      — skip the field entirely
//	form:"name,omitempty"  — leave the field at its zero value when
//	                         the form key is absent (default: assign
//	                         the zero value of the type explicitly)
func decodeForm(r *http.Request, dst any) error {
	val := reflect.ValueOf(dst)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("BindForm: dst must be a non-nil pointer to a struct")
	}
	val = val.Elem()
	if val.Kind() != reflect.Struct {
		return fmt.Errorf("BindForm: dst must point to a struct, got %s", val.Kind())
	}
	return decodeFormInto(r, val)
}

// decodeFormInto is the recursive worker behind decodeForm. It is
// split out so embedded structs can flow back into the same
// per-field loop without re-checking the dst pointer's shape.
func decodeFormInto(r *http.Request, val reflect.Value) error {
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		fld := typ.Field(i)
		target := val.Field(i)
		// Embedded structs (anonymous fields) bring their own
		// fields into the parent's form-key namespace — match
		// the Go convention where promoted fields look like they
		// belong to the outer type. Both value-embed and
		// pointer-embed are supported. Anonymous fields are
		// considered even when the underlying type is
		// unexported: their promoted fields may still be
		// exported and reflect.Value lets us descend into them.
		if fld.Anonymous {
			switch {
			case target.Kind() == reflect.Struct:
				if err := decodeFormInto(r, target); err != nil {
					return err
				}
				continue
			case target.Kind() == reflect.Ptr && target.Type().Elem().Kind() == reflect.Struct:
				if target.IsNil() {
					target.Set(reflect.New(target.Type().Elem()))
				}
				if err := decodeFormInto(r, target.Elem()); err != nil {
					return err
				}
				continue
			}
		}
		if !fld.IsExported() {
			continue
		}
		name, opts := parseFormTag(fld)
		if name == "-" {
			continue
		}

		// Multi-value: []string captures every entry the form key
		// carries (multi-select, checkbox group). The slice is
		// assigned even when only one value is present so the field
		// type stays predictable.
		if target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.String {
			vals, present := r.Form[name]
			if !present {
				if opts.omitempty {
					continue
				}
				target.Set(reflect.MakeSlice(target.Type(), 0, 0))
				continue
			}
			trimmed := make([]string, 0, len(vals))
			for _, v := range vals {
				trimmed = append(trimmed, strings.TrimSpace(v))
			}
			target.Set(reflect.ValueOf(trimmed))
			continue
		}

		raw, present := lookupFormValue(r, name)
		if !present && opts.omitempty {
			continue
		}
		if err := assignField(target, name, raw, present); err != nil {
			return err
		}
	}
	return nil
}

// formTagOpts collects the options on a `form:"..."` tag. Only
// omitempty is recognised today; new options can be added without
// touching call sites.
type formTagOpts struct {
	omitempty bool
}

// parseFormTag returns the form name and option set for a struct
// field. When no `form` tag is set the field name is converted to
// snake_case (FooBar → foo_bar) so HTML inputs that follow the
// codebase convention work without an explicit tag.
func parseFormTag(fld reflect.StructField) (string, formTagOpts) {
	tag := fld.Tag.Get("form")
	if tag == "" {
		return toSnakeCase(fld.Name), formTagOpts{}
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = toSnakeCase(fld.Name)
	}
	opts := formTagOpts{}
	for _, p := range parts[1:] {
		if strings.TrimSpace(p) == "omitempty" {
			opts.omitempty = true
		}
	}
	return name, opts
}

// toSnakeCase converts FooBarBaz → foo_bar_baz. The codebase already
// uses snake_case form names (see e.g. internal/web/handler_compliance.go
// CompliancePolicyCreate), so the default keeps DTOs compact when the
// names already line up.
//
// Acronym handling is intentionally naive (HTTPSPort → h_t_t_p_s_port);
// fields that mix acronyms with words should declare an explicit
// `form:"https_port"` tag rather than rely on the fallback.
func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lookupFormValue returns the trimmed value for name and a presence
// flag. r.Form is consulted (it already merges PostForm + query
// string); an unset key returns "" + present=false. For slice fields
// callers fetch the full r.Form[name] list directly via assignSlice.
func lookupFormValue(r *http.Request, name string) (string, bool) {
	vals, ok := r.Form[name]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return strings.TrimSpace(vals[0]), true
}

// assignField writes a single form value into the struct field.
// Pointer fields are auto-allocated only when the form key is
// present, so handlers can distinguish "field absent" from "field
// present, value empty" by inspecting the pointer's nil-ness. The
// []string case is handled directly in decodeForm.
func assignField(fld reflect.Value, name, raw string, present bool) error {
	if fld.Kind() == reflect.Ptr {
		if !present {
			return nil
		}
		if fld.IsNil() {
			fld.Set(reflect.New(fld.Type().Elem()))
		}
		return assignScalar(fld.Elem(), name, raw)
	}
	return assignScalar(fld, name, raw)
}

// assignScalar converts raw into the destination's Go type. Numeric
// errors quote the field name so the caller's flash message points
// at the offending input rather than at "invalid syntax" alone.
func assignScalar(fld reflect.Value, name, raw string) error {
	switch fld.Kind() {
	case reflect.String:
		fld.SetString(raw)
	case reflect.Bool:
		fld.SetBool(parseFormBool(raw))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if raw == "" {
			fld.SetInt(0)
			return nil
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("%s must be a whole number", name)
		}
		fld.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if raw == "" {
			fld.SetUint(0)
			return nil
		}
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("%s must be a non-negative whole number", name)
		}
		fld.SetUint(n)
	case reflect.Float32, reflect.Float64:
		if raw == "" {
			fld.SetFloat(0)
			return nil
		}
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("%s must be a number", name)
		}
		fld.SetFloat(n)
	default:
		return fmt.Errorf("%s has unsupported type %s", name, fld.Kind())
	}
	return nil
}

// nilIfEmpty collapses a `*string` whose payload is empty back to
// nil. Used by handlers that bind optional fields as `*string` to
// distinguish "absent" from "present-but-empty", but where the
// underlying service treats both cases identically (passing nil
// means "leave existing value alone").
func nilIfEmpty(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

// parseFormBool implements the HTML form bool convention: a
// checkbox that's checked submits its `value` (default "on"); when
// not checked, the key is omitted entirely. By the time we reach
// here the key WAS present, so any of the truthy literals counts;
// the empty string also counts (HTML <input type=hidden value="">
// pattern used to clear a checkbox on update).
func parseFormBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "1", "yes", "y", "checked":
		return true
	}
	return false
}
