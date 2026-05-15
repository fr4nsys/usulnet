// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ============================================================================
// AppError basics
// ============================================================================

func TestAppError_Error_WithWrapped(t *testing.T) {
	inner := fmt.Errorf("db connection failed")
	ae := Wrap(inner, CodeInternal, "service error")

	got := ae.Error()
	if !strings.Contains(got, CodeInternal) {
		t.Errorf("Error() missing code, got: %s", got)
	}
	if !strings.Contains(got, "service error") {
		t.Errorf("Error() missing message, got: %s", got)
	}
	if !strings.Contains(got, "db connection failed") {
		t.Errorf("Error() missing wrapped error, got: %s", got)
	}
}

func TestAppError_Error_WithoutWrapped(t *testing.T) {
	ae := New(CodeNotFound, "user not found")

	got := ae.Error()
	if !strings.Contains(got, CodeNotFound) {
		t.Errorf("Error() missing code, got: %s", got)
	}
	if !strings.Contains(got, "user not found") {
		t.Errorf("Error() missing message, got: %s", got)
	}
}

func TestAppError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("original error")
	ae := Wrap(inner, CodeInternal, "wrapped")

	if !errors.Is(ae.Unwrap(), inner) {
		t.Error("Unwrap() did not return the wrapped error")
	}
}

func TestAppError_Unwrap_Nil(t *testing.T) {
	ae := New(CodeInternal, "no inner")
	if ae.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no wrapped error")
	}
}

// ============================================================================
// Constructors
// ============================================================================

func TestNew(t *testing.T) {
	ae := New(CodeBadRequest, "bad input")

	if ae.Code != CodeBadRequest {
		t.Errorf("Code = %q, want %q", ae.Code, CodeBadRequest)
	}
	if ae.Message != "bad input" {
		t.Errorf("Message = %q, want %q", ae.Message, "bad input")
	}
	if ae.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusInternalServerError)
	}
}

func TestNewWithStatus(t *testing.T) {
	ae := NewWithStatus(CodeNotFound, "missing", http.StatusNotFound)

	if ae.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", ae.Code, CodeNotFound)
	}
	if ae.HTTPStatus != http.StatusNotFound {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusNotFound)
	}
}

func TestNewf(t *testing.T) {
	ae := Newf(CodeBadRequest, "field %s is %s", "email", "invalid")
	want := "field email is invalid"
	if ae.Message != want {
		t.Errorf("Message = %q, want %q", ae.Message, want)
	}
}

func TestWrap(t *testing.T) {
	inner := fmt.Errorf("timeout")
	ae := Wrap(inner, CodeTimeout, "upstream failed")

	if !errors.Is(ae.Err, inner) {
		t.Error("Wrap() did not preserve inner error")
	}
	if ae.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusInternalServerError)
	}
}

func TestWrapWithStatus(t *testing.T) {
	inner := fmt.Errorf("timeout")
	ae := WrapWithStatus(inner, CodeTimeout, "upstream failed", http.StatusGatewayTimeout)

	if !errors.Is(ae.Err, inner) {
		t.Error("WrapWithStatus() did not preserve inner error")
	}
	if ae.HTTPStatus != http.StatusGatewayTimeout {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusGatewayTimeout)
	}
}

// ============================================================================
// Builder methods
// ============================================================================

func TestWithDetails(t *testing.T) {
	details := map[string]interface{}{"field": "email"}
	ae := New(CodeBadRequest, "bad").WithDetails(details)

	if ae.Details["field"] != "email" {
		t.Errorf("Details[field] = %v, want email", ae.Details["field"])
	}
}

func TestWithDetail(t *testing.T) {
	ae := New(CodeBadRequest, "bad").WithDetail("key", "value")

	if ae.Details["key"] != "value" {
		t.Errorf("Details[key] = %v, want value", ae.Details["key"])
	}
}

func TestWithDetail_InitializesMap(t *testing.T) {
	ae := New(CodeBadRequest, "bad")
	if ae.Details != nil {
		t.Fatal("Details should be nil initially")
	}

	ae.WithDetail("key", "value")
	if ae.Details == nil {
		t.Fatal("WithDetail should initialize Details map")
	}
}

func TestWithHTTPStatus(t *testing.T) {
	ae := New(CodeBadRequest, "bad").WithHTTPStatus(http.StatusBadRequest)
	if ae.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusBadRequest)
	}
}

// ============================================================================
// Convenience constructors
// ============================================================================

func TestNotFound(t *testing.T) {
	ae := NotFound("user")
	if ae.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", ae.Code, CodeNotFound)
	}
	if ae.HTTPStatus != http.StatusNotFound {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusNotFound)
	}
	if !strings.Contains(ae.Message, "user") {
		t.Errorf("Message should contain resource name, got: %s", ae.Message)
	}
}

func TestAlreadyExists(t *testing.T) {
	ae := AlreadyExists("email")
	if ae.Code != CodeConflict {
		t.Errorf("Code = %q, want %q", ae.Code, CodeConflict)
	}
	if ae.HTTPStatus != http.StatusConflict {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusConflict)
	}
}

func TestInvalidInput(t *testing.T) {
	ae := InvalidInput("bad email")
	if ae.Code != CodeBadRequest {
		t.Errorf("Code = %q, want %q", ae.Code, CodeBadRequest)
	}
	if ae.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusBadRequest)
	}
}

func TestUnauthorized(t *testing.T) {
	ae := Unauthorized("invalid token")
	if ae.Code != CodeUnauthorized {
		t.Errorf("Code = %q, want %q", ae.Code, CodeUnauthorized)
	}
	if ae.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusUnauthorized)
	}
}

func TestForbidden(t *testing.T) {
	ae := Forbidden("no access")
	if ae.Code != CodeForbidden {
		t.Errorf("Code = %q, want %q", ae.Code, CodeForbidden)
	}
	if ae.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusForbidden)
	}
}

func TestInternal(t *testing.T) {
	ae := Internal("something broke")
	if ae.Code != CodeInternal {
		t.Errorf("Code = %q, want %q", ae.Code, CodeInternal)
	}
	if ae.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusInternalServerError)
	}
}

// ============================================================================
// ValidationFailed
// ============================================================================

func TestValidationFailed(t *testing.T) {
	fields := map[string]string{
		"email":    "invalid format",
		"username": "too short",
	}
	ae := ValidationFailed(fields)

	if ae.Code != CodeValidationFailed {
		t.Errorf("Code = %q, want %q", ae.Code, CodeValidationFailed)
	}
	if ae.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", ae.HTTPStatus, http.StatusBadRequest)
	}
	if ae.Details == nil {
		t.Fatal("Details should not be nil")
	}
	if ae.Details["email"] != "invalid format" {
		t.Errorf("Details[email] = %v, want 'invalid format'", ae.Details["email"])
	}
}

// ============================================================================
// GetAppError
// ============================================================================

func TestGetAppError_FromAppError(t *testing.T) {
	ae := New(CodeNotFound, "not found")
	got, ok := GetAppError(ae)
	if !ok {
		t.Fatal("GetAppError() should return true for AppError")
	}
	if got.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", got.Code, CodeNotFound)
	}
}

func TestGetAppError_FromWrapped(t *testing.T) {
	ae := New(CodeNotFound, "not found")
	wrapped := fmt.Errorf("layer: %w", ae)

	got, ok := GetAppError(wrapped)
	if !ok {
		t.Fatal("GetAppError() should find AppError in chain")
	}
	if got.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", got.Code, CodeNotFound)
	}
}

func TestGetAppError_FromPlainError(t *testing.T) {
	_, ok := GetAppError(fmt.Errorf("plain error"))
	if ok {
		t.Error("GetAppError() should return false for plain error")
	}
}

// ============================================================================
// HTTPStatusCode
// ============================================================================

func TestHTTPStatusCode_FromAppError(t *testing.T) {
	ae := NewWithStatus(CodeNotFound, "not found", http.StatusNotFound)
	if got := HTTPStatusCode(ae); got != http.StatusNotFound {
		t.Errorf("HTTPStatusCode() = %d, want %d", got, http.StatusNotFound)
	}
}

func TestHTTPStatusCode_FromSentinelErrors(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{ErrNotFound, http.StatusNotFound},
		{ErrAlreadyExists, http.StatusConflict},
		{ErrInvalidInput, http.StatusBadRequest},
		{ErrValidation, http.StatusBadRequest},
		{ErrUnauthorized, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{ErrConflict, http.StatusConflict},
		{ErrTimeout, http.StatusGatewayTimeout},
		{ErrServiceUnavailable, http.StatusServiceUnavailable},
		{ErrRateLimited, http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			if got := HTTPStatusCode(tt.err); got != tt.want {
				t.Errorf("HTTPStatusCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestHTTPStatusCode_UnknownError(t *testing.T) {
	if got := HTTPStatusCode(fmt.Errorf("unknown")); got != http.StatusInternalServerError {
		t.Errorf("HTTPStatusCode(unknown) = %d, want %d", got, http.StatusInternalServerError)
	}
}

func TestHTTPStatusCode_WrappedSentinel(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrNotFound)
	if got := HTTPStatusCode(wrapped); got != http.StatusNotFound {
		t.Errorf("HTTPStatusCode(wrapped ErrNotFound) = %d, want %d", got, http.StatusNotFound)
	}
}

// ============================================================================
// Typed errors
// ============================================================================

func TestNewNotFoundError(t *testing.T) {
	e := NewNotFoundError("user")
	if e.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", e.Code, CodeNotFound)
	}
	if e.HTTPStatus != http.StatusNotFound {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusNotFound)
	}
}

func TestNewAlreadyExistsError(t *testing.T) {
	e := NewAlreadyExistsError("email")
	if e.Code != CodeConflict {
		t.Errorf("Code = %q, want %q", e.Code, CodeConflict)
	}
	if e.HTTPStatus != http.StatusConflict {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusConflict)
	}
}

func TestNewValidationError(t *testing.T) {
	e := NewValidationError("field invalid")
	if e.Code != CodeValidationFailed {
		t.Errorf("Code = %q, want %q", e.Code, CodeValidationFailed)
	}
	if e.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusBadRequest)
	}
}

func TestNewUnauthorizedError(t *testing.T) {
	e := NewUnauthorizedError("no token")
	if e.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusUnauthorized)
	}
}

func TestNewForbiddenError(t *testing.T) {
	e := NewForbiddenError("no access")
	if e.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusForbidden)
	}
}

func TestNewConflictError(t *testing.T) {
	e := NewConflictError("duplicate")
	if e.Code != CodeConflict {
		t.Errorf("Code = %q, want %q", e.Code, CodeConflict)
	}
}

func TestNewInternalError(t *testing.T) {
	e := NewInternalError("crash")
	if e.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d, want %d", e.HTTPStatus, http.StatusInternalServerError)
	}
}

// ============================================================================
// Is*Error functions
// ============================================================================

func TestIsNotFoundError_TypedError(t *testing.T) {
	e := NewNotFoundError("user")
	if !IsNotFoundError(e) {
		t.Error("IsNotFoundError() should return true for NotFoundError")
	}
}

func TestIsNotFoundError_AppErrorWithCode(t *testing.T) {
	ae := New(CodeNotFound, "missing")
	if !IsNotFoundError(ae) {
		t.Error("IsNotFoundError() should return true for AppError with NOT_FOUND code")
	}
}

func TestIsNotFoundError_SentinelError(t *testing.T) {
	if !IsNotFoundError(ErrNotFound) {
		t.Error("IsNotFoundError() should return true for ErrNotFound sentinel")
	}
}

func TestIsNotFoundError_UnrelatedError(t *testing.T) {
	if IsNotFoundError(fmt.Errorf("something else")) {
		t.Error("IsNotFoundError() should return false for unrelated error")
	}
}

func TestIsConflictError_AlreadyExistsError(t *testing.T) {
	e := NewAlreadyExistsError("email")
	if !IsConflictError(e) {
		t.Error("IsConflictError() should return true for AlreadyExistsError")
	}
}

func TestIsConflictError_ConflictError(t *testing.T) {
	e := NewConflictError("duplicate")
	if !IsConflictError(e) {
		t.Error("IsConflictError() should return true for ConflictError")
	}
}

func TestIsConflictError_SentinelErrors(t *testing.T) {
	if !IsConflictError(ErrAlreadyExists) {
		t.Error("IsConflictError() should return true for ErrAlreadyExists")
	}
	if !IsConflictError(ErrConflict) {
		t.Error("IsConflictError() should return true for ErrConflict")
	}
}

func TestIsValidationError_TypedError(t *testing.T) {
	e := NewValidationError("bad input")
	if !IsValidationError(e) {
		t.Error("IsValidationError() should return true for ValidationError")
	}
}

func TestIsValidationError_AppErrorWithBadRequestCode(t *testing.T) {
	ae := New(CodeBadRequest, "invalid")
	if !IsValidationError(ae) {
		t.Error("IsValidationError() should return true for AppError with BAD_REQUEST code")
	}
}

func TestIsValidationError_SentinelErrors(t *testing.T) {
	if !IsValidationError(ErrValidation) {
		t.Error("IsValidationError() should return true for ErrValidation")
	}
	if !IsValidationError(ErrInvalidInput) {
		t.Error("IsValidationError() should return true for ErrInvalidInput")
	}
}

func TestIsUnauthorizedError_TypedError(t *testing.T) {
	e := NewUnauthorizedError("no token")
	if !IsUnauthorizedError(e) {
		t.Error("IsUnauthorizedError() should return true for UnauthorizedError")
	}
}

func TestIsUnauthorizedError_Sentinel(t *testing.T) {
	if !IsUnauthorizedError(ErrUnauthorized) {
		t.Error("IsUnauthorizedError() should return true for ErrUnauthorized")
	}
}

func TestIsForbiddenError_TypedError(t *testing.T) {
	e := NewForbiddenError("denied")
	if !IsForbiddenError(e) {
		t.Error("IsForbiddenError() should return true for ForbiddenError")
	}
}

func TestIsForbiddenError_Sentinel(t *testing.T) {
	if !IsForbiddenError(ErrForbidden) {
		t.Error("IsForbiddenError() should return true for ErrForbidden")
	}
}

// ============================================================================
// errors.Is / errors.As delegation
// ============================================================================

func TestIs_DelegatesToStdlib(t *testing.T) {
	if !Is(ErrNotFound, ErrNotFound) {
		t.Error("Is() should delegate to errors.Is")
	}
	wrapped := fmt.Errorf("wrap: %w", ErrNotFound)
	if !Is(wrapped, ErrNotFound) {
		t.Error("Is() should work with wrapped errors")
	}
}

func TestAs_DelegatesToStdlib(t *testing.T) {
	ae := New(CodeNotFound, "not found")
	var target *AppError
	if !As(ae, &target) {
		t.Error("As() should find AppError")
	}
}

// ============================================================================
// Typed errors can be extracted via errors.As with their own type
// ============================================================================

func TestTypedErrors_CanBeExtractedViaErrorsAs(t *testing.T) {
	// Each typed error should be extractable via errors.As with its own type
	var nfe *NotFoundError
	if !errors.As(NewNotFoundError("user"), &nfe) {
		t.Error("NotFoundError should be extractable via errors.As")
	}

	var aee *AlreadyExistsError
	if !errors.As(NewAlreadyExistsError("email"), &aee) {
		t.Error("AlreadyExistsError should be extractable via errors.As")
	}

	var ve *ValidationError
	if !errors.As(NewValidationError("invalid"), &ve) {
		t.Error("ValidationError should be extractable via errors.As")
	}

	var ue *UnauthorizedError
	if !errors.As(NewUnauthorizedError("no token"), &ue) {
		t.Error("UnauthorizedError should be extractable via errors.As")
	}

	var fe *ForbiddenError
	if !errors.As(NewForbiddenError("denied"), &fe) {
		t.Error("ForbiddenError should be extractable via errors.As")
	}

	var ce *ConflictError
	if !errors.As(NewConflictError("dup"), &ce) {
		t.Error("ConflictError should be extractable via errors.As")
	}

	var ie *InternalError
	if !errors.As(NewInternalError("crash"), &ie) {
		t.Error("InternalError should be extractable via errors.As")
	}
}

func TestTypedErrors_ImplementErrorInterface(t *testing.T) {
	// All typed errors implement the error interface
	var _ error = NewNotFoundError("test")
	var _ error = NewAlreadyExistsError("test")
	var _ error = NewValidationError("test")
	var _ error = NewUnauthorizedError("test")
	var _ error = NewForbiddenError("test")
	var _ error = NewConflictError("test")
	var _ error = NewInternalError("test")
}

// ============================================================================
// Sentinel errors are distinct
// ============================================================================

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrNotFound, ErrAlreadyExists, ErrInvalidInput, ErrUnauthorized,
		ErrForbidden, ErrInternal, ErrTimeout, ErrConflict,
		ErrServiceUnavailable, ErrRateLimited, ErrValidation,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel errors should be distinct: %v == %v", a, b)
			}
		}
	}
}
