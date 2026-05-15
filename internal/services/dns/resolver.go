// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dnsResolver implements Resolver via the standard library's
// net.Resolver, pointing at a configured upstream. Centralizing the
// resolver lets tests inject a fake without having to mock UDP.
type dnsResolver struct {
	addr     string
	resolver *net.Resolver
}

func newDNSResolver(addr string) *dnsResolver {
	r := &dnsResolver{
		addr: addr,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
	r.resolver.Dial = r.dial
	return r
}

func (r *dnsResolver) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, r.addr)
}

// LookupTXT queries the configured upstream for TXT records.
func (r *dnsResolver) LookupTXT(ctx context.Context, fqdn string) ([]string, error) {
	if fqdn == "" {
		return nil, fmt.Errorf("dns: empty fqdn")
	}
	return r.resolver.LookupTXT(ctx, fqdn)
}
