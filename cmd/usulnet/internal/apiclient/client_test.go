// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package apiclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewResolvesEnvFallback confirms that an empty Options.BaseURL /
// Options.Token reads the documented env vars (EnvBaseURL / EnvToken).
func TestNewResolvesEnvFallback(t *testing.T) {
	t.Setenv(EnvBaseURL, "http://example.local")
	t.Setenv(EnvToken, "TOK")
	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.BaseURL() != "http://example.local" {
		t.Errorf("BaseURL: got %q", c.BaseURL())
	}
	if c.Token() != "TOK" {
		t.Errorf("Token: got %q", c.Token())
	}
}

// TestNewExplicitOptionsBeatEnv verifies the precedence — flag-equivalent
// (Options field) wins when both are set.
func TestNewExplicitOptionsBeatEnv(t *testing.T) {
	t.Setenv(EnvBaseURL, "http://env-host")
	t.Setenv(EnvToken, "FROM_ENV")
	c, err := New(Options{BaseURL: "http://flag-host", Token: "FROM_FLAG"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.BaseURL() != "http://flag-host" {
		t.Errorf("explicit BaseURL should win: got %q", c.BaseURL())
	}
	if c.Token() != "FROM_FLAG" {
		t.Errorf("explicit Token should win: got %q", c.Token())
	}
}

// TestNewMissingBaseURLReturnsErrConfig pins the typed-error contract —
// no BaseURL anywhere produces *ErrConfig so the caller can map it to
// an exit code.
func TestNewMissingBaseURLReturnsErrConfig(t *testing.T) {
	t.Setenv(EnvBaseURL, "")
	t.Setenv(EnvToken, "")
	_, err := New(Options{})
	if err == nil {
		t.Fatal("expected ErrConfig when no BaseURL is configured")
	}
	var cfg *ErrConfig
	if !errors.As(err, &cfg) {
		t.Errorf("expected *ErrConfig, got %T (%v)", err, err)
	}
}

// TestNewTrimsTrailingSlash documents that BaseURL is normalized so
// paths don't end up with double slashes.
func TestNewTrimsTrailingSlash(t *testing.T) {
	c, err := New(Options{BaseURL: "http://host/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.BaseURL() != "http://host" {
		t.Errorf("trailing slash should be trimmed: %q", c.BaseURL())
	}
}

// TestDoSetsAuthHeader exercises the JSON path end-to-end: Authorization
// header is set, Content-Type sticks on POST, response decodes into out.
func TestDoSetsAuthHeader(t *testing.T) {
	var gotAuth, gotContentType, gotAccept string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL, Token: "T"})
	var resp struct {
		OK bool `json:"ok"`
	}
	err := c.Do(context.Background(), http.MethodPost, "/x",
		map[string]string{"key": "value"}, &resp)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "Bearer T" {
		t.Errorf("Authorization: got %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type: got %q", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept: got %q", gotAccept)
	}
	if !strings.Contains(gotBody, `"key":"value"`) {
		t.Errorf("body: got %q", gotBody)
	}
	if !resp.OK {
		t.Error("response not decoded")
	}
}

// TestDoUnauthorizedReturnsErrAuth maps 401 → *ErrAuth.
func TestDoUnauthorizedReturnsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL})
	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected ErrAuth on 401")
	}
	var ae *ErrAuth
	if !errors.As(err, &ae) {
		t.Errorf("expected *ErrAuth, got %T", err)
	}
}

// TestDoForbiddenReturnsErrAuth maps 403 → *ErrAuth.
func TestDoForbiddenReturnsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL})
	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected ErrAuth on 403")
	}
	var ae *ErrAuth
	if !errors.As(err, &ae) {
		t.Errorf("expected *ErrAuth, got %T", err)
	}
}

// TestDoServerErrorReturnsErrStatus maps 5xx → *ErrStatus with body.
func TestDoServerErrorReturnsErrStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL})
	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected ErrStatus on 500")
	}
	var se *ErrStatus
	if !errors.As(err, &se) {
		t.Fatalf("expected *ErrStatus, got %T", err)
	}
	if !strings.Contains(string(se.Body), "boom") {
		t.Errorf("ErrStatus.Body should contain the response payload, got %q", se.Body)
	}
}

// TestDoNetworkFailureReturnsErrNetwork covers the dial-failed path.
// We point at a closed listener to trigger ECONNREFUSED.
func TestDoNetworkFailureReturnsErrNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close() // ensure subsequent connections refuse

	c, _ := New(Options{BaseURL: addr})
	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected ErrNetwork on dial failure")
	}
	var ne *ErrNetwork
	if !errors.As(err, &ne) {
		t.Errorf("expected *ErrNetwork, got %T", err)
	}
}

// TestNewRequestSetsAuthAndURL pins the contract for the multipart /
// raw-byte paths that bypass Do(): NewRequest builds a request bound to
// the configured BaseURL with the Authorization header set.
func TestNewRequestSetsAuthAndURL(t *testing.T) {
	c, _ := New(Options{BaseURL: "http://host", Token: "T"})
	req, err := c.NewRequest(context.Background(), http.MethodPost, "/x", strings.NewReader("body"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.URL.String() != "http://host/x" {
		t.Errorf("URL: got %q", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer T" {
		t.Errorf("Authorization: got %q", got)
	}
}

// TestStreamParsesSSE exercises a minimal event-stream — two events,
// each with an `event:` line and a `data:` line, separated by blank
// lines. The onEvent callback receives them in order.
func TestStreamParsesSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: hello\ndata: world\n\nevent: goodbye\ndata: friend\n\n")
	}))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL})

	type event struct{ name, data string }
	var got []event
	err := c.Stream(context.Background(), "/events", func(name, data string) {
		got = append(got, event{name, data})
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(got), got)
	}
	if got[0] != (event{"hello", "world"}) {
		t.Errorf("event 0: %+v", got[0])
	}
	if got[1] != (event{"goodbye", "friend"}) {
		t.Errorf("event 1: %+v", got[1])
	}
}
