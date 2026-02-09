// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package errors provides standardized HTTP error responses for the API.
// All API handlers should use these functions to return consistent error responses.
package errors

import (
	"encoding/json"
	"net/http"
)

// ErrorCode represents a machine-readable error code.
type ErrorCode string

const (
	// Authentication/Authorization errors
	ErrCodeUnauthorized     ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden        ErrorCode = "FORBIDDEN"
	ErrCodeInvalidToken     ErrorCode = "INVALID_TOKEN"
	ErrCodeExpiredToken     ErrorCode = "EXPIRED_TOKEN"
	ErrCodeRevokedToken     ErrorCode = "REVOKED_TOKEN"
	ErrCodeInvalidAPIKey    ErrorCode = "INVALID_API_KEY"
	ErrCodeSessionExpired   ErrorCode = "SESSION_EXPIRED"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"

	// Validation errors
	ErrCodeValidation       ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput     ErrorCode = "INVALID_INPUT"
	ErrCodeMissingField     ErrorCode = "MISSING_FIELD"
	ErrCodeInvalidFormat    ErrorCode = "INVALID_FORMAT"

	// Resource errors
	ErrCodeNotFound         ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists    ErrorCode = "ALREADY_EXISTS"
	ErrCodeConflict         ErrorCode = "CONFLICT"
	ErrCodeGone             ErrorCode = "GONE"

	// Rate limiting
	ErrCodeRateLimited      ErrorCode = "RATE_LIMITED"
	ErrCodeTooManyRequests  ErrorCode = "TOO_MANY_REQUESTS"

	// Server errors
	ErrCodeInternal         ErrorCode = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeTimeout          ErrorCode = "TIMEOUT"
	ErrCodeDatabaseError    ErrorCode = "DATABASE_ERROR"

	// Docker specific errors
	ErrCodeDockerError      ErrorCode = "DOCKER_ERROR"
	ErrCodeContainerNotFound ErrorCode = "CONTAINER_NOT_FOUND"
	ErrCodeImageNotFound    ErrorCode = "IMAGE_NOT_FOUND"
	ErrCodeNetworkNotFound  ErrorCode = "NETWORK_NOT_FOUND"
	ErrCodeVolumeNotFound   ErrorCode = "VOLUME_NOT_FOUND"
	ErrCodeHostNotFound     ErrorCode = "HOST_NOT_FOUND"
	ErrCodeHostUnreachable  ErrorCode = "HOST_UNREACHABLE"

	// License errors
	ErrCodeLicenseRequired  ErrorCode = "LICENSE_REQUIRED"
	ErrCodeLicenseExpired   ErrorCode = "LICENSE_EXPIRED"
	ErrCodeLicenseInvalid   ErrorCode = "LICENSE_INVALID"
	ErrCodeFeatureDisabled  ErrorCode = "FEATURE_DISABLED"
)

// APIError represents a standardized API error response.
type APIError struct {
	// HTTP status code
	Status int `json:"status"`

	// Machine-readable error code
	Code ErrorCode `json:"code"`

	// Human-readable error message
	Message string `json:"message"`

	// Optional detailed information about the error
	Details any `json:"details,omitempty"`

	// Request ID for tracing (populated by middleware)
	RequestID string `json:"request_id,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return e.Message
}

// ValidationError contains details about validation failures.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   any    `json:"value,omitempty"`
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

// WriteError writes a JSON error response to the http.ResponseWriter.
func WriteError(w http.ResponseWriter, err *APIError) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(err)
}

// WriteErrorWithRequestID writes an error response with request ID.
func WriteErrorWithRequestID(w http.ResponseWriter, err *APIError, requestID string) {
	err.RequestID = requestID
	WriteError(w, err)
}

// NewError creates a new APIError.
func NewError(status int, code ErrorCode, message string) *APIError {
	return &APIError{
		Status:  status,
		Code:    code,
		Message: message,
	}
}

// NewErrorWithDetails creates a new APIError with additional details.
func NewErrorWithDetails(status int, code ErrorCode, message string, details any) *APIError {
	return &APIError{
		Status:  status,
		Code:    code,
		Message: message,
		Details: details,
	}
}

// ============================================================================
// Common error constructors
// ============================================================================

// Unauthorized returns a 401 Unauthorized error.
func Unauthorized(message string) *APIError {
	if message == "" {
		message = "Authentication required"
	}
	return NewError(http.StatusUnauthorized, ErrCodeUnauthorized, message)
}

// InvalidToken returns a 401 error for invalid JWT tokens.
func InvalidToken(message string) *APIError {
	if message == "" {
		message = "Invalid or malformed token"
	}
	return NewError(http.StatusUnauthorized, ErrCodeInvalidToken, message)
}

// ExpiredToken returns a 401 error for expired tokens.
func ExpiredToken() *APIError {
	return NewError(http.StatusUnauthorized, ErrCodeExpiredToken, "Token has expired")
}

// RevokedToken returns a 401 error for revoked tokens.
func RevokedToken() *APIError {
	return NewError(http.StatusUnauthorized, ErrCodeRevokedToken, "Token has been revoked")
}

// InvalidAPIKey returns a 401 error for invalid API keys.
func InvalidAPIKey() *APIError {
	return NewError(http.StatusUnauthorized, ErrCodeInvalidAPIKey, "Invalid API key")
}

// InvalidCredentials returns a 401 error for invalid login credentials.
func InvalidCredentials() *APIError {
	return NewError(http.StatusUnauthorized, ErrCodeInvalidCredentials, "Invalid username or password")
}

// Forbidden returns a 403 Forbidden error.
func Forbidden(message string) *APIError {
	if message == "" {
		message = "Access denied"
	}
	return NewError(http.StatusForbidden, ErrCodeForbidden, message)
}

// NotFound returns a 404 Not Found error.
func NotFound(resource string) *APIError {
	message := "Resource not found"
	if resource != "" {
		message = resource + " not found"
	}
	return NewError(http.StatusNotFound, ErrCodeNotFound, message)
}

// ContainerNotFound returns a 404 error for containers.
func ContainerNotFound(containerID string) *APIError {
	return NewErrorWithDetails(
		http.StatusNotFound,
		ErrCodeContainerNotFound,
		"Container not found",
		map[string]string{"container_id": containerID},
	)
}

// ImageNotFound returns a 404 error for images.
func ImageNotFound(imageRef string) *APIError {
	return NewErrorWithDetails(
		http.StatusNotFound,
		ErrCodeImageNotFound,
		"Image not found",
		map[string]string{"image": imageRef},
	)
}

// HostNotFound returns a 404 error for Docker hosts.
func HostNotFound(hostID string) *APIError {
	return NewErrorWithDetails(
		http.StatusNotFound,
		ErrCodeHostNotFound,
		"Host not found",
		map[string]string{"host_id": hostID},
	)
}

// AlreadyExists returns a 409 Conflict error for duplicate resources.
func AlreadyExists(resource string) *APIError {
	message := "Resource already exists"
	if resource != "" {
		message = resource + " already exists"
	}
	return NewError(http.StatusConflict, ErrCodeAlreadyExists, message)
}

// Conflict returns a 409 Conflict error.
func Conflict(message string) *APIError {
	if message == "" {
		message = "Resource conflict"
	}
	return NewError(http.StatusConflict, ErrCodeConflict, message)
}

// ValidationFailed returns a 400 Bad Request error with validation details.
func ValidationFailed(errors ValidationErrors) *APIError {
	return NewErrorWithDetails(
		http.StatusBadRequest,
		ErrCodeValidation,
		"Validation failed",
		errors,
	)
}

// InvalidInput returns a 400 Bad Request error.
func InvalidInput(message string) *APIError {
	if message == "" {
		message = "Invalid input"
	}
	return NewError(http.StatusBadRequest, ErrCodeInvalidInput, message)
}

// MissingField returns a 400 error for missing required fields.
func MissingField(field string) *APIError {
	return NewErrorWithDetails(
		http.StatusBadRequest,
		ErrCodeMissingField,
		"Missing required field",
		map[string]string{"field": field},
	)
}

// RateLimited returns a 429 Too Many Requests error.
func RateLimited(retryAfter int) *APIError {
	return NewErrorWithDetails(
		http.StatusTooManyRequests,
		ErrCodeRateLimited,
		"Rate limit exceeded",
		map[string]int{"retry_after_seconds": retryAfter},
	)
}

// Internal returns a 500 Internal Server Error.
func Internal(message string) *APIError {
	if message == "" {
		message = "Internal server error"
	}
	return NewError(http.StatusInternalServerError, ErrCodeInternal, message)
}

// ServiceUnavailable returns a 503 Service Unavailable error.
func ServiceUnavailable(message string) *APIError {
	if message == "" {
		message = "Service temporarily unavailable"
	}
	return NewError(http.StatusServiceUnavailable, ErrCodeServiceUnavailable, message)
}

// DockerError returns a 500 error for Docker-related failures.
func DockerError(message string) *APIError {
	if message == "" {
		message = "Docker operation failed"
	}
	return NewError(http.StatusInternalServerError, ErrCodeDockerError, message)
}

// HostUnreachable returns a 503 error when a Docker host is unreachable.
func HostUnreachable(hostID string) *APIError {
	return NewErrorWithDetails(
		http.StatusServiceUnavailable,
		ErrCodeHostUnreachable,
		"Docker host is unreachable",
		map[string]string{"host_id": hostID},
	)
}

// LicenseRequired returns a 402 Payment Required error.
func LicenseRequired(feature string) *APIError {
	return NewErrorWithDetails(
		http.StatusPaymentRequired,
		ErrCodeLicenseRequired,
		"This feature requires a valid license",
		map[string]string{"feature": feature},
	)
}

// LicenseExpired returns a 402 error for expired licenses.
func LicenseExpired() *APIError {
	return NewError(http.StatusPaymentRequired, ErrCodeLicenseExpired, "License has expired")
}

// FeatureDisabled returns a 403 error for disabled features.
func FeatureDisabled(feature string) *APIError {
	return NewErrorWithDetails(
		http.StatusForbidden,
		ErrCodeFeatureDisabled,
		"Feature is disabled",
		map[string]string{"feature": feature},
	)
}

// Timeout returns a 504 Gateway Timeout error.
func Timeout(message string) *APIError {
	if message == "" {
		message = "Request timed out"
	}
	return NewError(http.StatusGatewayTimeout, ErrCodeTimeout, message)
}

// ============================================================================
// Conversion from pkg/errors
// ============================================================================

// FromAppError converts an AppError from pkg/errors to an APIError.
// This is used to bridge internal errors to HTTP responses.
func FromAppError(err error) *APIError {
	// Try to extract AppError type
	type appError interface {
		Error() string
		Unwrap() error
	}
	type withCode interface {
		appError
		GetCode() string
		GetHTTPStatus() int
		GetDetails() map[string]interface{}
	}

	// Check if it's our custom error type
	if ae, ok := err.(interface {
		Error() string
	}); ok {
		// Try to get code and status via reflection-like interface checking
		var code ErrorCode = ErrCodeInternal
		status := http.StatusInternalServerError
		message := ae.Error()
		var details any

		// Try to get the code field
		if coder, ok := err.(interface{ Code() string }); ok {
			code = ErrorCode(coder.Code())
		}

		// Try to get HTTP status
		if stater, ok := err.(interface{ HTTPStatus() int }); ok {
			if s := stater.HTTPStatus(); s != 0 {
				status = s
			}
		}

		// Try to get details
		if detailer, ok := err.(interface{ Details() map[string]interface{} }); ok {
			details = detailer.Details()
		}

		return &APIError{
			Status:  status,
			Code:    code,
			Message: message,
			Details: details,
		}
	}

	// Fallback for plain errors
	return Internal(err.Error())
}

// FromError converts any error to an APIError.
// Uses error text and defaults to internal error.
func FromError(err error) *APIError {
	if err == nil {
		return nil
	}

	// Check if it's already an APIError
	if apiErr, ok := err.(*APIError); ok {
		return apiErr
	}

	// Try to convert from AppError
	return FromAppError(err)
}
