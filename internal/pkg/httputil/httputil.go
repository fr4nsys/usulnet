// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package httputil provides HTTP utility functions.
package httputil

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// JSONResponse writes a JSON response.
func JSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// ErrorResponse writes an error response.
func ErrorResponse(w http.ResponseWriter, status int, message string) {
	JSONResponse(w, status, map[string]interface{}{
		"error":   true,
		"message": message,
		"status":  status,
	})
}

// HandleError converts an error to an appropriate HTTP response.
func HandleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	// Use helper functions if available, otherwise type assertions
	var notFoundErr *apperrors.NotFoundError
	if errors.As(err, &notFoundErr) {
		ErrorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	var alreadyExistsErr *apperrors.AlreadyExistsError
	if errors.As(err, &alreadyExistsErr) {
		ErrorResponse(w, http.StatusConflict, err.Error())
		return
	}

	var validationErr *apperrors.ValidationError
	if errors.As(err, &validationErr) {
		ErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	var unauthorizedErr *apperrors.UnauthorizedError
	if errors.As(err, &unauthorizedErr) {
		ErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	var forbiddenErr *apperrors.ForbiddenError
	if errors.As(err, &forbiddenErr) {
		ErrorResponse(w, http.StatusForbidden, err.Error())
		return
	}

	var conflictErr *apperrors.ConflictError
	if errors.As(err, &conflictErr) {
		ErrorResponse(w, http.StatusConflict, err.Error())
		return
	}

	var internalErr *apperrors.InternalError
	if errors.As(err, &internalErr) {
		ErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Default to internal server error
	ErrorResponse(w, http.StatusInternalServerError, err.Error())
}

// PaginatedResponse writes a paginated JSON response.
func PaginatedResponse(w http.ResponseWriter, data interface{}, total int64, page, perPage int) {
	totalPages := (int(total) + perPage - 1) / perPage

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"data": data,
		"pagination": map[string]interface{}{
			"total":       total,
			"page":        page,
			"per_page":    perPage,
			"total_pages": totalPages,
			"has_next":    page < totalPages,
			"has_prev":    page > 1,
		},
	})
}

// QueryInt parses an integer query parameter with a default value.
func QueryInt(r *http.Request, key string, defaultValue int) int {
	str := r.URL.Query().Get(key)
	if str == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(str)
	if err != nil {
		return defaultValue
	}

	return val
}

// QueryBool parses a boolean query parameter.
func QueryBool(r *http.Request, key string) bool {
	str := r.URL.Query().Get(key)
	return str == "true" || str == "1" || str == "yes"
}

// StreamResponse streams data from a reader to the response writer.
func StreamResponse(w http.ResponseWriter, reader io.Reader) {
	flusher, ok := w.(http.Flusher)

	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if ok {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

// BindJSON decodes JSON from request body.
func BindJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(v); err != nil {
		return err
	}

	return nil
}

// Created writes a 201 Created response with location header.
func Created(w http.ResponseWriter, location string, data interface{}) {
	if location != "" {
		w.Header().Set("Location", location)
	}
	JSONResponse(w, http.StatusCreated, data)
}

// NoContent writes a 204 No Content response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Accepted writes a 202 Accepted response.
func Accepted(w http.ResponseWriter, data interface{}) {
	JSONResponse(w, http.StatusAccepted, data)
}
