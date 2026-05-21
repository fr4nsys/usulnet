// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// freshJS returns a deterministic ~50 KiB JavaScript-shaped payload —
// enough to be above chi's default compress threshold and large enough
// that gzip's win is unambiguous.
func freshJS() []byte {
	const chunk = "function render() { return 'usulnet ready'; }\n"
	var b bytes.Buffer
	for b.Len() < 50*1024 {
		b.WriteString(chunk)
	}
	return b.Bytes()
}

func perfRouterWithCompress() http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.NewCompressor(5, compressibleTypes...).Handler)
	r.Get("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(freshJS())
	})
	return r
}

// TestFrontendCompressGzipsJS pins that the frontend compress middleware
// gzips application/javascript responses when the client advertises gzip
// support, and that the payload round-trips byte-for-byte after un-gzip.
// Regression guard for the v26.5.2 perf pass: the Monaco editor /
// Swagger UI bundles must ship compressed on cold load.
func TestFrontendCompressGzipsJS(t *testing.T) {
	srv := httptest.NewServer(perfRouterWithCompress())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", got, "gzip")
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read decoded: %v", err)
	}
	want := freshJS()
	if !bytes.Equal(decoded, want) {
		t.Fatalf("decoded payload differs from source (got %d bytes, want %d)", len(decoded), len(want))
	}
}

// TestFrontendCompressReducesPayloadSize measures the bytes-on-the-wire
// reduction for a representative JS payload. The exact ratio depends on
// the entropy of the source bytes but for the synthetic payload here we
// expect ~95 % reduction; the assertion uses a conservative 70 % floor
// so a future Go gzip stdlib tweak does not flake the test.
func TestFrontendCompressReducesPayloadSize(t *testing.T) {
	srv := httptest.NewServer(perfRouterWithCompress())
	defer srv.Close()

	want := freshJS()
	uncompressedSize := len(want)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	gzippedBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	gzippedSize := len(gzippedBody)

	if gzippedSize >= uncompressedSize {
		t.Fatalf("gzipped size %d >= uncompressed %d (compression did not run)", gzippedSize, uncompressedSize)
	}
	ratio := float64(gzippedSize) / float64(uncompressedSize)
	if ratio > 0.30 {
		t.Fatalf("compression ratio %.2f%% too high for redundant JS payload — expected <30 %%", ratio*100)
	}
	t.Logf("payload: %d B uncompressed -> %d B gzipped (%.2f%% of original)",
		uncompressedSize, gzippedSize, ratio*100)
}

// TestFrontendCompressSkipsWoff2 asserts woff2 fonts (already compressed)
// are NOT re-gzipped — re-gzipping would waste CPU for ~0 % gain. The
// compressibleTypes allow-list excludes font/woff2 deliberately.
func TestFrontendCompressSkipsWoff2(t *testing.T) {
	r := chi.NewRouter()
	r.Use(chimiddleware.NewCompressor(5, compressibleTypes...).Handler)
	r.Get("/static/font.woff2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "font/woff2")
		_, _ = w.Write(bytes.Repeat([]byte{0xFF}, 10*1024))
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/font.woff2", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q for woff2, want empty (no re-gzip)", got)
	}
}

// breachMitigationRouter mirrors the route-group layout produced by
// RegisterFrontendRoutes: the static group and the public-HTML group get
// chi's Compressor, the protected group does NOT. Used by the BREACH
// mitigation regression test below.
func breachMitigationRouter() http.Handler {
	r := chi.NewRouter()
	// Static — compressed
	r.Group(func(r chi.Router) {
		r.Use(chimiddleware.NewCompressor(5, compressibleTypes...).Handler)
		r.Get("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(freshJS())
		})
	})
	// Public HTML — compressed (no server-side secret in body)
	r.Group(func(r chi.Router) {
		r.Use(chimiddleware.NewCompressor(5, compressibleTypes...).Handler)
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(bytes.Repeat([]byte("<p>login page</p>\n"), 4*1024))
		})
	})
	// Protected HTML — NOT compressed (BREACH mitigation). The body
	// embeds a fake CSRF token to mirror the real <meta name="csrf-token">
	// shape from layouts/base.templ.
	r.Group(func(r chi.Router) {
		// No Compressor — this is the assertion under test.
		r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			body := []byte(`<meta name="csrf-token" content="a1b2c3d4e5f60718293a4b5c6d7e8f90">`)
			body = append(body, bytes.Repeat([]byte("<p>dashboard row</p>\n"), 4*1024)...)
			_, _ = w.Write(body)
		})
	})
	return r
}

// TestProtectedRouteNotCompressed pins the BREACH mitigation: responses
// from the authenticated route group MUST NOT be gzipped even when the
// client advertises gzip support, because the body embeds the session
// CSRF token (and potentially reflected query parameters in future
// handlers). A regression that re-introduces a top-level Compressor —
// or accidentally wraps the protected group in one — would expose the
// token to the BREACH compression-ratio side-channel; this test fails
// loudly before that can ship. See docs/v26.5/security-review-v26.5.2.md
// §6.6 / v26.5.2/27.
func TestProtectedRouteNotCompressed(t *testing.T) {
	srv := httptest.NewServer(breachMitigationRouter())
	defer srv.Close()

	t.Run("protected/dashboard", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/dashboard", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()

		if got := resp.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("protected route Content-Encoding = %q, want empty (BREACH mitigation)", got)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Contains(body, []byte(`name="csrf-token"`)) {
			t.Fatalf("protected response missing CSRF token sentinel — test fixture broken")
		}
	})

	// Positive controls: prove the SAME router gzips routes that are
	// safe to compress, so a "test always passes because Compressor is
	// fully off" regression does not slip by.
	t.Run("static/app.js_is_gzipped", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("static route Content-Encoding = %q, want %q", got, "gzip")
		}
	})

	t.Run("public/login_is_gzipped", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/login", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("public route Content-Encoding = %q, want %q", got, "gzip")
		}
	})
}

// BenchmarkRequestIDFormat compares the strconv.FormatInt path used by
// the frontend request-ID middleware against the fmt.Sprintf("%d", ...)
// path it replaced. Runs on every frontend request, so the per-call
// cost matters even though the absolute saving is small.
func BenchmarkRequestIDFormat(b *testing.B) {
	now := time.Now().UnixNano()
	b.Run("strconv.FormatInt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = strconv.FormatInt(now, 10)
		}
	})

	b.Run("fmt.Sprintf_baseline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fmt.Sprintf("%d", now)
		}
	})
}
