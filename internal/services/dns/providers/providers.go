// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package providers provides the explicit registration helper that
// the wiring layer uses to attach the bundled DNS provider plugins to
// a Registry. v26.2.7 relied on init() side effects; this build is
// explicit so a missing plugin is a static error, not a "the menu is
// empty and nobody knows why".
package providers

import (
	"github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/cloudflare"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/digitalocean"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/rfc2136"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/route53"
)

// RegisterAll registers every bundled plugin. Call exactly once at
// boot; double-registration returns an error rather than silently
// overwriting.
func RegisterAll(reg *dns.Registry) error {
	for _, fn := range []func(*dns.Registry) error{
		cloudflare.Register,
		route53.Register,
		digitalocean.Register,
		rfc2136.Register,
	} {
		if err := fn(reg); err != nil {
			return err
		}
	}
	return nil
}
