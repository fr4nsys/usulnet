// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/license"
)

// LicenseProvider is the interface that the license.Provider satisfies.
// It is defined here to avoid an import cycle (middleware ← license).
type LicenseProvider interface {
	GetLicense(ctx context.Context) (*license.Info, error)
	HasFeature(ctx context.Context, feature license.Feature) bool
	IsValid(ctx context.Context) bool
	GetLimits() license.Limits
}

// Context key for license info.
const LicenseContextKey contextKey = "license"

// ============================================================================
// License middleware
// ============================================================================

// LicenseConfig contains configuration for the license middleware.
type LicenseConfig struct {
	Provider     LicenseProvider
	AddToContext bool
}

// License returns a middleware that adds license info to the request context.
func License(config LicenseConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.Provider != nil && config.AddToContext {
				info, _ := config.Provider.GetLicense(r.Context())
				if info != nil {
					ctx := context.WithValue(r.Context(), LicenseContextKey, info)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireFeature returns a middleware that requires a specific license feature.
func RequireFeature(provider LicenseProvider, feature license.Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !provider.HasFeature(r.Context(), feature) {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseRequired(string(feature)), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePaid returns a middleware that requires Business or Enterprise edition.
func RequirePaid(provider LicenseProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, err := provider.GetLicense(r.Context())
			if err != nil || info == nil || info.Edition == license.CE {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseRequired("business"), requestID)
				return
			}
			if info.IsExpired() {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseExpired(), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireEnterprise returns a middleware that requires Enterprise edition.
func RequireEnterprise(provider LicenseProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, err := provider.GetLicense(r.Context())
			if err != nil || info == nil || info.Edition != license.Enterprise {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseRequired("enterprise"), requestID)
				return
			}
			if info.IsExpired() {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseExpired(), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireValidLicense returns a middleware that requires any valid (non-expired) license.
func RequireValidLicense(provider LicenseProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !provider.IsValid(r.Context()) {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.LicenseExpired(), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireLimit returns a middleware that checks a resource limit.
func RequireLimit(provider LicenseProvider, resourceName string, currentCountFn func(*http.Request) int, getLimitFn func(license.Limits) int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limits := provider.GetLimits()
			limit := getLimitFn(limits)

			// 0 = unlimited
			if limit == 0 {
				next.ServeHTTP(w, r)
				return
			}

			current := currentCountFn(r)
			if current >= limit {
				requestID := GetRequestID(r.Context())
				upgradeMsg := "Upgrade to usulnet Business for more " + resourceName
				info, _ := provider.GetLicense(r.Context())
				if info != nil && info.Edition == license.Business {
					upgradeMsg = "Upgrade to usulnet Enterprise for unlimited " + resourceName
				}
				err := apierrors.NewErrorWithDetails(
					http.StatusPaymentRequired,
					apierrors.ErrCodeLicenseRequired,
					"Resource limit reached",
					map[string]any{
						"resource": resourceName,
						"current":  current,
						"limit":    limit,
						"upgrade":  upgradeMsg,
					},
				)
				apierrors.WriteErrorWithRequestID(w, err, requestID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// Context helpers
// ============================================================================

// GetLicenseFromContext retrieves license info from the request context.
func GetLicenseFromContext(ctx context.Context) *license.Info {
	if info, ok := ctx.Value(LicenseContextKey).(*license.Info); ok {
		return info
	}
	return nil
}

// IsPaidFromContext checks if the current license is Business or Enterprise.
func IsPaidFromContext(ctx context.Context) bool {
	info := GetLicenseFromContext(ctx)
	return info != nil && info.Edition != license.CE && info.Valid
}
