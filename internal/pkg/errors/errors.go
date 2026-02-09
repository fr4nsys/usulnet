// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors
var (
	ErrNotFound           = errors.New("not found")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidInput       = errors.New("invalid input")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrInternal           = errors.New("internal error")
	ErrTimeout            = errors.New("timeout")
	ErrConflict           = errors.New("conflict")
	ErrServiceUnavailable = errors.New("service unavailable")
	ErrRateLimited        = errors.New("rate limited")
	ErrValidation         = errors.New("validation error")
)

// AppError represents an application-specific error with code and details
type AppError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Err        error                  `json:"-"`
	HTTPStatus int                    `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewWithStatus creates a new AppError with HTTP status
func NewWithStatus(code, message string, status int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
	}
}

// Wrap wraps an existing error with code and message
func Wrap(err error, code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// WrapWithStatus wraps an error with HTTP status
func WrapWithStatus(err error, code, message string, status int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		HTTPStatus: status,
	}
}

// WithDetails adds details to an AppError
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithDetail adds a single detail to an AppError
func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithHTTPStatus sets the HTTP status code
func (e *AppError) WithHTTPStatus(status int) *AppError {
	e.HTTPStatus = status
	return e
}

// Is checks if the error matches the target
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// GetAppError extracts an AppError from an error chain
func GetAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// HTTPStatusCode returns the HTTP status code for an error
func HTTPStatusCode(err error) int {
	if appErr, ok := GetAppError(err); ok && appErr.HTTPStatus != 0 {
		return appErr.HTTPStatus
	}

	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrValidation):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrTimeout):
		return http.StatusGatewayTimeout
	case errors.Is(err, ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// NotFound creates a not found error
func NotFound(resource string) *AppError {
	return NewWithStatus(CodeNotFound, fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

// AlreadyExists creates an already exists error
func AlreadyExists(resource string) *AppError {
	return NewWithStatus(CodeConflict, fmt.Sprintf("%s already exists", resource), http.StatusConflict)
}

// InvalidInput creates an invalid input error
func InvalidInput(message string) *AppError {
	return NewWithStatus(CodeBadRequest, message, http.StatusBadRequest)
}

// Unauthorized creates an unauthorized error
func Unauthorized(message string) *AppError {
	return NewWithStatus(CodeUnauthorized, message, http.StatusUnauthorized)
}

// Forbidden creates a forbidden error
func Forbidden(message string) *AppError {
	return NewWithStatus(CodeForbidden, message, http.StatusForbidden)
}

// Internal creates an internal error
func Internal(message string) *AppError {
	return NewWithStatus(CodeInternal, message, http.StatusInternalServerError)
}

// LimitExceeded creates a license limit exceeded error (HTTP 402 Payment Required).
func LimitExceeded(resource string, current, limit int) *AppError {
	return NewWithStatus(
		CodeLimitExceeded,
		fmt.Sprintf("%s limit reached (%d/%d). Upgrade your license for more.", resource, current, limit),
		http.StatusPaymentRequired,
	).WithDetails(map[string]interface{}{
		"resource": resource,
		"current":  current,
		"limit":    limit,
	})
}

// ValidationFailed creates a validation error with field details
func ValidationFailed(fields map[string]string) *AppError {
	details := make(map[string]interface{})
	for k, v := range fields {
		details[k] = v
	}
	return NewWithStatus(CodeValidationFailed, "validation failed", http.StatusBadRequest).WithDetails(details)
}

// Specific error types for type assertions
// These wrap AppError but allow for errors.As() type checking

// NotFoundError represents a not found error
type NotFoundError struct {
	*AppError
}

// AlreadyExistsError represents a resource already exists error
type AlreadyExistsError struct {
	*AppError
}

// ValidationError represents a validation error
type ValidationError struct {
	*AppError
}

// UnauthorizedError represents an unauthorized error
type UnauthorizedError struct {
	*AppError
}

// ForbiddenError represents a forbidden error
type ForbiddenError struct {
	*AppError
}

// ConflictError represents a conflict error
type ConflictError struct {
	*AppError
}

// InternalError represents an internal error
type InternalError struct {
	*AppError
}

// NewNotFoundError creates a typed not found error
func NewNotFoundError(resource string) *NotFoundError {
	return &NotFoundError{
		AppError: NewWithStatus(CodeNotFound, fmt.Sprintf("%s not found", resource), http.StatusNotFound),
	}
}

// NewAlreadyExistsError creates a typed already exists error
func NewAlreadyExistsError(resource string) *AlreadyExistsError {
	return &AlreadyExistsError{
		AppError: NewWithStatus(CodeConflict, fmt.Sprintf("%s already exists", resource), http.StatusConflict),
	}
}

// NewValidationError creates a typed validation error
func NewValidationError(message string) *ValidationError {
	return &ValidationError{
		AppError: NewWithStatus(CodeValidationFailed, message, http.StatusBadRequest),
	}
}

// NewUnauthorizedError creates a typed unauthorized error
func NewUnauthorizedError(message string) *UnauthorizedError {
	return &UnauthorizedError{
		AppError: NewWithStatus(CodeUnauthorized, message, http.StatusUnauthorized),
	}
}

// NewForbiddenError creates a typed forbidden error
func NewForbiddenError(message string) *ForbiddenError {
	return &ForbiddenError{
		AppError: NewWithStatus(CodeForbidden, message, http.StatusForbidden),
	}
}

// NewConflictError creates a typed conflict error
func NewConflictError(message string) *ConflictError {
	return &ConflictError{
		AppError: NewWithStatus(CodeConflict, message, http.StatusConflict),
	}
}

// NewInternalError creates a typed internal error
func NewInternalError(message string) *InternalError {
	return &InternalError{
		AppError: NewWithStatus(CodeInternal, message, http.StatusInternalServerError),
	}
}

// IsNotFoundError checks if error is a NotFoundError
func IsNotFoundError(err error) bool {
	var e *NotFoundError
	if errors.As(err, &e) {
		return true
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeNotFound
	}
	return errors.Is(err, ErrNotFound)
}

// IsConflictError checks if error is a conflict error
func IsConflictError(err error) bool {
	var e *AlreadyExistsError
	if errors.As(err, &e) {
		return true
	}
	var c *ConflictError
	if errors.As(err, &c) {
		return true
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeConflict
	}
	return errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrConflict)
}

// IsValidationError checks if error is a validation error
func IsValidationError(err error) bool {
	var e *ValidationError
	if errors.As(err, &e) {
		return true
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeValidationFailed || appErr.Code == CodeBadRequest
	}
	return errors.Is(err, ErrValidation) || errors.Is(err, ErrInvalidInput)
}

// IsUnauthorizedError checks if error is an unauthorized error
func IsUnauthorizedError(err error) bool {
	var e *UnauthorizedError
	if errors.As(err, &e) {
		return true
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeUnauthorized
	}
	return errors.Is(err, ErrUnauthorized)
}

// IsForbiddenError checks if error is a forbidden error
func IsForbiddenError(err error) bool {
	var e *ForbiddenError
	if errors.As(err, &e) {
		return true
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeForbidden
	}
	return errors.Is(err, ErrForbidden)
}

// Newf creates a new AppError with formatted message
func Newf(code, format string, args ...interface{}) *AppError {
	return New(code, fmt.Sprintf(format, args...))
}
