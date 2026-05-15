// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package errors provides standardized HTTP error responses for the API.
// All API handlers should use these functions to return consistent error responses.
package errors

import (
	"encoding/json"
	"errors"
	"net/http"

	pkgerrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// ErrorCode represents a machine-readable error code.
type ErrorCode string

const (
	// Authentication/Authorization errors
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrCodeInvalidToken       ErrorCode = "INVALID_TOKEN"
	ErrCodeExpiredToken       ErrorCode = "EXPIRED_TOKEN"
	ErrCodeRevokedToken       ErrorCode = "REVOKED_TOKEN"
	ErrCodeInvalidAPIKey      ErrorCode = "INVALID_API_KEY"
	ErrCodeSessionExpired     ErrorCode = "SESSION_EXPIRED"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"

	// Validation errors
	ErrCodeValidation    ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput  ErrorCode = "INVALID_INPUT"
	ErrCodeMissingField  ErrorCode = "MISSING_FIELD"
	ErrCodeInvalidFormat ErrorCode = "INVALID_FORMAT"

	// Resource errors
	ErrCodeNotFound      ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists ErrorCode = "ALREADY_EXISTS"
	ErrCodeConflict      ErrorCode = "CONFLICT"
	ErrCodeGone          ErrorCode = "GONE"

	// Rate limiting
	ErrCodeRateLimited     ErrorCode = "RATE_LIMITED"
	ErrCodeTooManyRequests ErrorCode = "TOO_MANY_REQUESTS"

	// Server errors
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"

	// Docker specific errors
	ErrCodeDockerError       ErrorCode = "DOCKER_ERROR"
	ErrCodeContainerNotFound ErrorCode = "CONTAINER_NOT_FOUND"
	ErrCodeImageNotFound     ErrorCode = "IMAGE_NOT_FOUND"
	ErrCodeNetworkNotFound   ErrorCode = "NETWORK_NOT_FOUND"
	ErrCodeVolumeNotFound    ErrorCode = "VOLUME_NOT_FOUND"
	ErrCodeHostNotFound      ErrorCode = "HOST_NOT_FOUND"
	ErrCodeHostUnreachable   ErrorCode = "HOST_UNREACHABLE"

	// License errors. Only LicenseInvalid is emitted in the AGPL build —
	// it covers the JWT activation path. There is no LICENSE_REQUIRED /
	// LICENSE_EXPIRED / FEATURE_DISABLED case anymore: every feature is
	// available unconditionally (principle 2 in
	// docs/0526/x/principles.md).
	ErrCodeLicenseInvalid ErrorCode = "LICENSE_INVALID"

	// Not implemented
	ErrCodeNotImplemented ErrorCode = "NOT_IMPLEMENTED"

	// Feature not supported by the active backend (e.g. proxy streams
	// against Caddy). HTTP 422 so clients can distinguish a translatable
	// request from server-side failure.
	ErrCodeFeatureNotSupported ErrorCode = "FEATURE_NOT_SUPPORTED"

	// Recon / privacy module (v26.5.0). See docs/v26.5/technical-notes.md
	// ("Error response shape"). These codes are documented in lower_snake
	// because the recon RFC pins them as the public contract.
	ErrCodeOwnershipRequired       ErrorCode = "ownership_required"
	ErrCodeOwnershipPending        ErrorCode = "ownership_pending"
	ErrCodeEngineUnavailable       ErrorCode = "engine_unavailable"
	ErrCodeModuleDisabled          ErrorCode = "module_disabled"
	ErrCodeAcknowledgementRequired ErrorCode = "acknowledgement_required"
	ErrCodeUnsupportedTargetType   ErrorCode = "unsupported_target_type"
	ErrCodeProfileTargetMismatch   ErrorCode = "profile_target_mismatch"
	ErrCodeArtifactTooLarge        ErrorCode = "artifact_too_large"
	ErrCodeMIMENotSupported        ErrorCode = "mime_not_supported"
)

// ============================================================================
// Recon module error constructors
// ============================================================================

// ModuleDisabled returns a 404 used to hide all recon routes when
// cfg.Recon.Enabled is false. The 404 (rather than 403) is intentional
// — the RFC requires the module to be invisible when off.
func ModuleDisabled() *APIError {
	return NewError(http.StatusNotFound, ErrCodeModuleDisabled, "Resource not found")
}

// AcknowledgementRequired returns a 409 when an admin has not yet
// confirmed the recon legal notice. Until acknowledged, all recon /
// metadata routes (except the ack endpoint itself) return this.
func AcknowledgementRequired() *APIError {
	return NewError(http.StatusConflict, ErrCodeAcknowledgementRequired,
		"Recon module is enabled but awaiting admin acknowledgement of the legal notice")
}

// OwnershipRequired returns a 403 when a scan is attempted against a
// target whose ownership has not been verified.
func OwnershipRequired(targetID string) *APIError {
	return NewErrorWithDetails(
		http.StatusForbidden,
		ErrCodeOwnershipRequired,
		"Target ownership must be verified before scanning",
		map[string]string{"target_id": targetID},
	)
}

// ArtifactTooLarge returns a 413 for uploads above the configured cap.
func ArtifactTooLarge(limit int64) *APIError {
	return NewErrorWithDetails(
		http.StatusRequestEntityTooLarge,
		ErrCodeArtifactTooLarge,
		"Uploaded artifact exceeds size limit",
		map[string]int64{"max_bytes": limit},
	)
}

// UnsupportedTargetType returns a 400 for target types the API does not
// accept (or that don't make sense for the called endpoint).
func UnsupportedTargetType(typ string) *APIError {
	return NewErrorWithDetails(
		http.StatusBadRequest,
		ErrCodeUnsupportedTargetType,
		"Unsupported target type",
		map[string]string{"type": typ},
	)
}

// APIError represents a standardized API error response.
//
// The JSON shape is documented in OpenAPI as containing a top-level
// "success" boolean (always false for errors) alongside status/code/
// message. The Success field is serialized explicitly (no omitempty)
// so error responses are unambiguous to clients that distinguish
// success/failure envelopes.
type APIError struct {
	// Success is always false on error responses. Present so clients
	// can use a uniform success/error envelope check.
	Success bool `json:"success"`

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

// FeatureNotSupported returns a 422 when the requested feature cannot
// be applied by the active backend (e.g. raw TCP/UDP streams against
// the Caddy proxy backend). The body includes a human-readable message
// explaining which backend rejected the feature.
func FeatureNotSupported(message string) *APIError {
	if message == "" {
		message = "Feature not supported by active backend"
	}
	return NewError(http.StatusUnprocessableEntity, ErrCodeFeatureNotSupported, message)
}

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

// Timeout returns a 504 Gateway Timeout error.
func Timeout(message string) *APIError {
	if message == "" {
		message = "Request timed out"
	}
	return NewError(http.StatusGatewayTimeout, ErrCodeTimeout, message)
}

// NotImplemented returns a 501 Not Implemented error.
func NotImplemented(message string) *APIError {
	if message == "" {
		message = "This endpoint is not yet implemented"
	}
	return NewError(http.StatusNotImplemented, ErrCodeNotImplemented, message)
}

// ============================================================================
// Conversion from pkg/errors
// ============================================================================

// FromAppError converts an AppError from pkg/errors to an APIError.
// This is used to bridge internal errors to HTTP responses.
func FromAppError(err error) *APIError {
	// Extract *pkgerrors.AppError from the error chain.
	var appErr *pkgerrors.AppError
	if errors.As(err, &appErr) {
		code := ErrorCode(appErr.Code)
		if code == "" {
			code = ErrCodeInternal
		}

		status := appErr.HTTPStatus
		if status == 0 {
			status = http.StatusInternalServerError
		}

		// Use the Message field for a clean message rather than Error()
		// which includes the code prefix and wrapped error.
		message := appErr.Message
		if message == "" {
			message = err.Error()
		}

		var details any
		if len(appErr.Details) > 0 {
			details = appErr.Details
		}

		return &APIError{
			Status:  status,
			Code:    code,
			Message: message,
			Details: details,
		}
	}

	// Fallback: use sentinel error mapping from pkg/errors.
	status := pkgerrors.HTTPStatusCode(err)
	if status != http.StatusInternalServerError {
		code := httpStatusToErrorCode(status)
		return &APIError{
			Status:  status,
			Code:    code,
			Message: err.Error(),
		}
	}

	// Plain error — return as internal.
	return Internal(err.Error())
}

// httpStatusToErrorCode maps an HTTP status to an appropriate error code.
func httpStatusToErrorCode(status int) ErrorCode {
	switch status {
	case http.StatusBadRequest:
		return ErrCodeInvalidInput
	case http.StatusUnauthorized:
		return ErrCodeUnauthorized
	case http.StatusForbidden:
		return ErrCodeForbidden
	case http.StatusNotFound:
		return ErrCodeNotFound
	case http.StatusConflict:
		return ErrCodeConflict
	case http.StatusTooManyRequests:
		return ErrCodeRateLimited
	case http.StatusGatewayTimeout:
		return ErrCodeTimeout
	case http.StatusServiceUnavailable:
		return ErrCodeServiceUnavailable
	default:
		return ErrCodeInternal
	}
}

// FromError converts any error to an APIError.
// Uses error text and defaults to internal error.
func FromError(err error) *APIError {
	if err == nil {
		return nil
	}

	// Check if it's already an APIError
	apiErr := &APIError{}
	if errors.As(err, &apiErr) {
		return apiErr
	}

	// Try to convert from AppError
	return FromAppError(err)
}
