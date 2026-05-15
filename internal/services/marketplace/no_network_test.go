// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package marketplace

import (
	"context"
	stderrors "errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestStart_NoOutboundCalls asserts that bootstrapping the marketplace
// service — constructor + catalog hydration with the real embedded
// source — does not attempt any TCP dial. The marketplace is supposed
// to be 100% offline; any code path that tries to reach a network
// service is a regression of the "no call-home" principle.
//
// We achieve this by patching http.DefaultTransport to fail every
// connection attempt and counting hits. Anything that comes through
// the std http stack lands here. Both `net.Dial` (used by raw TCP
// callers) and crypto/tls.Dial go through net.Dialer.DialContext, so
// the DialContext hook captures the broad surface.
//
// Code that opens a raw `net.Dial` outside http.DefaultTransport would
// bypass this hook; we accept that limitation because the marketplace
// package's only conceivable network surface is HTTP fetching.
func TestStart_NoOutboundCalls(t *testing.T) {
	var dialAttempts int32

	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	http.DefaultTransport = &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			atomic.AddInt32(&dialAttempts, 1)
			t.Errorf("unexpected outbound dial: %s %s", network, addr)
			return nil, stderrors.New("marketplace: outbound network calls are forbidden")
		},
		ResponseHeaderTimeout: 1 * time.Millisecond,
	}

	apps := newMemAppRepo()
	insts := newMemInstallRepo()
	reviews := newMemReviewRepo()
	svc := NewService(apps, insts, reviews, &fakeStackInstaller{}, NewEmbeddedCatalog(), nil)

	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("HydrateCatalog: %v", err)
	}

	if got := atomic.LoadInt32(&dialAttempts); got != 0 {
		t.Errorf("marketplace start triggered %d outbound dials; expected 0", got)
	}
	if len(apps.rows) == 0 {
		t.Error("embedded catalog produced zero apps — fixture missing?")
	}
}
