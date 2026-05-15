// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"

	"github.com/fr4nsys/usulnet/internal/license"
)

// LicenseProvider is the interface that the license.Provider satisfies.
// It is defined here so handlers and the license context middleware can
// reference license state without pulling in the full provider package.
type LicenseProvider interface {
	GetLicense(ctx context.Context) (*license.Info, error)
	HasFeature(ctx context.Context, feature license.Feature) bool
	IsValid(ctx context.Context) bool
	GetLimits() license.Limits
}

// LicenseContextKey is the request-context key under which license
// info is stashed by the License middleware.
const LicenseContextKey contextKey = "license"

// LicenseConfig configures the License middleware.
type LicenseConfig struct {
	Provider     LicenseProvider
	AddToContext bool
}

// License returns middleware that attaches the current license.Info to
// the request context for downstream handlers that want to render the
// support-tier banner. It performs no enforcement — the AGPL build
// unlocks every feature unconditionally and does not gate any route on
// edition or feature flags.
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

// GetLicenseFromContext retrieves license info from the request context.
// Returns nil when no License middleware ran on the request.
func GetLicenseFromContext(ctx context.Context) *license.Info {
	if info, ok := ctx.Value(LicenseContextKey).(*license.Info); ok {
		return info
	}
	return nil
}
