// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package request contains standardized request DTOs for the API.
package request

import (
	"net/http"
	"strconv"
	"strings"
)

// ============================================================================
// Pagination
// ============================================================================

// Pagination contains pagination parameters.
type Pagination struct {
	Page    int `json:"page" validate:"min=1"`
	PerPage int `json:"per_page" validate:"min=1,max=100"`
}

// DefaultPagination returns default pagination values.
func DefaultPagination() Pagination {
	return Pagination{
		Page:    1,
		PerPage: 20,
	}
}

// Offset returns the database offset for the current page.
func (p Pagination) Offset() int {
	return (p.Page - 1) * p.PerPage
}

// Limit returns the database limit.
func (p Pagination) Limit() int {
	return p.PerPage
}

// PaginationFromRequest extracts pagination from query parameters.
func PaginationFromRequest(r *http.Request) Pagination {
	p := DefaultPagination()

	if page := r.URL.Query().Get("page"); page != "" {
		if v, err := strconv.Atoi(page); err == nil && v > 0 {
			p.Page = v
		}
	}

	if perPage := r.URL.Query().Get("per_page"); perPage != "" {
		if v, err := strconv.Atoi(perPage); err == nil && v > 0 && v <= 100 {
			p.PerPage = v
		}
	}

	return p
}

// ============================================================================
// Sorting
// ============================================================================

// Sort contains sorting parameters.
type Sort struct {
	Field string `json:"sort_by"`
	Order string `json:"sort_order"` // "asc" or "desc"
}

// DefaultSort returns default sort values.
func DefaultSort(field string) Sort {
	return Sort{
		Field: field,
		Order: "asc",
	}
}

// IsDesc returns true if sort order is descending.
func (s Sort) IsDesc() bool {
	return strings.ToLower(s.Order) == "desc"
}

// SortFromRequest extracts sort parameters from query parameters.
func SortFromRequest(r *http.Request, defaultField string, allowedFields []string) Sort {
	s := DefaultSort(defaultField)

	if field := r.URL.Query().Get("sort_by"); field != "" {
		// Validate field is in allowed list
		for _, allowed := range allowedFields {
			if strings.EqualFold(field, allowed) {
				s.Field = allowed
				break
			}
		}
	}

	if order := r.URL.Query().Get("sort_order"); order != "" {
		order = strings.ToLower(order)
		if order == "asc" || order == "desc" {
			s.Order = order
		}
	}

	return s
}

// ============================================================================
// Filtering
// ============================================================================

// Filter represents a single filter condition.
type Filter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // "eq", "ne", "gt", "lt", "gte", "lte", "like", "in"
	Value    any    `json:"value"`
}

// Filters is a collection of filters.
type Filters []Filter

// FiltersFromRequest extracts filters from query parameters.
// Supports simple equality filters: ?name=foo&status=running
// and operator filters: ?created_at[gte]=2024-01-01
func FiltersFromRequest(r *http.Request, allowedFields []string) Filters {
	filters := make(Filters, 0)
	allowed := make(map[string]bool)
	for _, f := range allowedFields {
		allowed[f] = true
	}

	for key, values := range r.URL.Query() {
		if len(values) == 0 {
			continue
		}

		// Check for operator syntax: field[operator]
		field, operator := parseFilterKey(key)
		if !allowed[field] {
			continue
		}

		// Handle multiple values as "in" operator
		if len(values) > 1 {
			filters = append(filters, Filter{
				Field:    field,
				Operator: "in",
				Value:    values,
			})
		} else {
			filters = append(filters, Filter{
				Field:    field,
				Operator: operator,
				Value:    values[0],
			})
		}
	}

	return filters
}

// parseFilterKey parses a filter key like "created_at[gte]" into field and operator.
func parseFilterKey(key string) (field, operator string) {
	if idx := strings.Index(key, "["); idx > 0 {
		field = key[:idx]
		if endIdx := strings.Index(key, "]"); endIdx > idx {
			operator = key[idx+1 : endIdx]
		}
	} else {
		field = key
		operator = "eq"
	}
	return
}

// ============================================================================
// List options
// ============================================================================

// ListOptions combines pagination, sorting, and filtering.
type ListOptions struct {
	Pagination
	Sort
	Filters Filters
	Search  string // Full-text search query
}

// ListOptionsFromRequest extracts list options from a request.
func ListOptionsFromRequest(r *http.Request, defaultSort string, allowedSortFields, allowedFilterFields []string) ListOptions {
	return ListOptions{
		Pagination: PaginationFromRequest(r),
		Sort:       SortFromRequest(r, defaultSort, allowedSortFields),
		Filters:    FiltersFromRequest(r, allowedFilterFields),
		Search:     r.URL.Query().Get("q"),
	}
}

// ============================================================================
// Auth requests
// ============================================================================

// Login represents a login request.
type Login struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

// RefreshToken represents a token refresh request.
type RefreshToken struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// ChangePassword represents a password change request.
type ChangePassword struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=72"`
}

// ============================================================================
// Common request helpers
// ============================================================================

// IDsRequest represents a request with a list of IDs.
type IDsRequest struct {
	IDs []string `json:"ids" validate:"required,min=1,dive,required"`
}

// BulkActionRequest represents a bulk action request.
type BulkActionRequest struct {
	IDs    []string `json:"ids" validate:"required,min=1,dive,required"`
	Action string   `json:"action" validate:"required"`
}

// ============================================================================
// Parameter extraction helpers
// ============================================================================

// PathParam extracts a path parameter from chi router context.
// Usage: id := request.PathParam(r, "id")
func PathParam(r *http.Request, name string) string {
	// chi stores path params in context, but we need to import chi to access them
	// This is a placeholder - the actual implementation will use chi.URLParam
	return r.PathValue(name) // Go 1.22+ native path params
}

// QueryParam extracts a query parameter with a default value.
func QueryParam(r *http.Request, name, defaultValue string) string {
	if v := r.URL.Query().Get(name); v != "" {
		return v
	}
	return defaultValue
}

// QueryParamInt extracts an integer query parameter with a default value.
func QueryParamInt(r *http.Request, name string, defaultValue int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}

// QueryParamBool extracts a boolean query parameter.
func QueryParamBool(r *http.Request, name string) bool {
	v := strings.ToLower(r.URL.Query().Get(name))
	return v == "true" || v == "1" || v == "yes"
}

// QueryParamSlice extracts a slice query parameter (comma-separated).
func QueryParamSlice(r *http.Request, name string) []string {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
