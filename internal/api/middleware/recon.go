// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
)

// ReconAckChecker reports whether the recon module's legal notice has
// been acknowledged by an admin. Implementations should cache the
// result in memory after first read so that the middleware does not
// hammer the database on every request.
type ReconAckChecker interface {
	IsAcknowledged(ctx context.Context) (bool, error)
}

// ReconFeatureFlag returns a middleware that short-circuits with a 404
// when the recon module is disabled. The 404 (rather than a 403) is
// deliberate — when the feature flag is off the module is invisible
// to the API surface (docs/recon.md §7.4).
func ReconFeatureFlag(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.ModuleDisabled(), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReconAcknowledgement returns a middleware that returns 409
// acknowledgement_required until an admin records consent to the
// recon legal notice. Requests are allowed through once IsAcknowledged
// returns true; transient errors fail closed (also 409, with the same
// code) so a database hiccup cannot bypass the gate.
//
// The acknowledgement endpoint POST /api/v1/recon/_ack must be
// registered outside the wrapper (the router places it on a sibling
// branch) — this middleware will block it otherwise.
func ReconAcknowledgement(checker ReconAckChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.AcknowledgementRequired(), requestID)
				return
			}
			ok, err := checker.IsAcknowledged(r.Context())
			if err != nil || !ok {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.AcknowledgementRequired(), requestID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
