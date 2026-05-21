// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/spf13/cobra"
)

// TestStaticCompletionRegistration pins the wiring of every enum flag in
// the CLI tree. A regression that drops a completion (e.g. someone
// reintroduces --output without re-registering it) flips this test red.
//
// The matrix mirrors the registrations in main.go init() and recon.go
// init(); when a new enum flag lands the matrix MUST grow alongside it.
func TestStaticCompletionRegistration(t *testing.T) {
	type matrixEntry struct {
		path string
		flag string
		want []string
	}
	matrix := []matrixEntry{
		{path: "usulnet serve", flag: "mode", want: completeServeModes},
		{path: "usulnet serve", flag: "component", want: completeServeComponents},
		{path: "usulnet", flag: "output", want: completeOutputFormats},
		{path: "usulnet recon scan report", flag: "format", want: completeReportFormats},
		{path: "usulnet recon findings list", flag: "severity", want: completeSeverityLevels},
	}

	for _, m := range matrix {
		t.Run(m.path+" --"+m.flag, func(t *testing.T) {
			cmd := findCommand(rootCmd, m.path)
			if cmd == nil {
				t.Fatalf("command %q not found", m.path)
			}
			fn, ok := cmd.GetFlagCompletionFunc(m.flag)
			if !ok {
				// Fall back to inherited completion (e.g. --output is on rootCmd).
				if rf, rok := rootCmd.GetFlagCompletionFunc(m.flag); rok {
					fn = rf
					ok = true
				}
			}
			if !ok {
				t.Fatalf("--%s on %q has no completion func", m.flag, m.path)
			}
			got, directive := fn(cmd, nil, "")
			if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
				t.Errorf("--%s completion must use NoFileComp (got %v)", m.flag, directive)
			}
			if !equalSorted(got, m.want) {
				t.Errorf("--%s completion mismatch:\n  got  %v\n  want %v", m.flag, got, m.want)
			}
		})
	}
}

// TestDynamicCompletionRegistration pins the positionals and flags that
// must carry a ValidArgsFunction. Each entry is the command path and the
// completer it should resolve to (by pointer identity, not by call —
// calls would require a live server).
func TestDynamicCompletionRegistration(t *testing.T) {
	cases := []struct {
		path string
		want func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)
	}{
		{"usulnet recon target add", completeReconTargetAddArgs},
		{"usulnet recon target verify", completeReconTargetIDs},
		{"usulnet recon scan start", completeReconTargetIDs},
		{"usulnet recon scan status", completeReconScanIDs},
		{"usulnet recon scan cancel", completeReconScanIDs},
		{"usulnet recon scan report", completeReconScanIDs},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			cmd := findCommand(rootCmd, c.path)
			if cmd == nil {
				t.Fatalf("command %q not found", c.path)
			}
			if cmd.ValidArgsFunction == nil {
				t.Fatalf("command %q has no ValidArgsFunction", c.path)
			}
			if !sameFunc(cmd.ValidArgsFunction, c.want) {
				t.Errorf("command %q ValidArgsFunction points at the wrong implementation", c.path)
			}
		})
	}

	// Dynamic flag completers
	flagCases := []struct {
		path string
		flag string
		want func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)
	}{
		{"usulnet recon scan start", "profile", completeReconProfileNames},
		{"usulnet recon findings list", "target", completeReconTargetIDs},
	}
	for _, c := range flagCases {
		t.Run(c.path+" --"+c.flag, func(t *testing.T) {
			cmd := findCommand(rootCmd, c.path)
			if cmd == nil {
				t.Fatalf("command %q not found", c.path)
			}
			fn, ok := cmd.GetFlagCompletionFunc(c.flag)
			if !ok {
				t.Fatalf("--%s on %q has no completion func", c.flag, c.path)
			}
			if !sameFunc(fn, c.want) {
				t.Errorf("--%s on %q points at the wrong completer", c.flag, c.path)
			}
		})
	}
}

// TestCompleteReconTargetAddArgs covers the small static branching in
// the target-add positional completer.
func TestCompleteReconTargetAddArgs(t *testing.T) {
	got, directive := completeReconTargetAddArgs(rootCmd, nil, "")
	if !equalSorted(got, completeTargetTypes) {
		t.Errorf("position 0 should offer target types, got %v", got)
	}
	if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Errorf("position 0 directive must include NoFileComp, got %v", directive)
	}

	got, _ = completeReconTargetAddArgs(rootCmd, []string{"email"}, "")
	if len(got) != 0 {
		t.Errorf("position 1 should not propose any value, got %v", got)
	}
}

// TestCompleteReconTargetIDs_Server exercises the dynamic completer
// against an httptest server. It covers the happy path: the API returns
// a target list and the completer formats each entry as "<id>\t<desc>".
func TestCompleteReconTargetIDs_Server(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/recon/targets" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]targetResponse{
			{ID: "11111111-1111-1111-1111-111111111111", Type: "email", Value: "a@b"},
			{ID: "22222222-2222-2222-2222-222222222222", Type: "domain", Value: "example.com"},
		})
	}))
	defer srv.Close()

	withReconClientEnv(t, srv.URL, "")
	got, directive := completeReconTargetIDs(rootCmd, nil, "")
	if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Errorf("dynamic completer must use NoFileComp, got %v", directive)
	}
	want := []string{
		"11111111-1111-1111-1111-111111111111\temail:a@b",
		"22222222-2222-2222-2222-222222222222\tdomain:example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("completion mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestCompleteReconScanIDs_Server covers the scan-id completer's happy
// path and the "<id>\t<status>" formatting it emits.
func TestCompleteReconScanIDs_Server(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/recon/scans" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]scanResponse{
			{ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "running"},
			{ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Status: ""},
		})
	}))
	defer srv.Close()

	withReconClientEnv(t, srv.URL, "")
	got, _ := completeReconScanIDs(rootCmd, nil, "")
	want := []string{
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\trunning",
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\tscan",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("completion mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestCompleteReconProfileNames_Server covers the profile-name completer
// and its fallback description ("profile") when Kind is empty.
func TestCompleteReconProfileNames_Server(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/recon/profiles" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]profileResponse{
			{ID: "1", Name: "default", Kind: "builtin"},
			{ID: "2", Name: "custom-1", Kind: ""},
		})
	}))
	defer srv.Close()

	withReconClientEnv(t, srv.URL, "")
	got, _ := completeReconProfileNames(rootCmd, nil, "")
	want := []string{"default\tbuiltin", "custom-1\tprofile"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("completion mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestCompleteReconTargetIDs_NoServer guards the "no API URL configured"
// branch: the completer must return NoFileComp with no values so the
// shell does not silently fall through to filename completion.
func TestCompleteReconTargetIDs_NoServer(t *testing.T) {
	withReconClientEnv(t, "", "")
	got, directive := completeReconTargetIDs(rootCmd, nil, "")
	if len(got) != 0 {
		t.Errorf("no-server completer must return empty, got %v", got)
	}
	if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Errorf("no-server completer must still set NoFileComp, got %v", directive)
	}
}

// =============================================================================
// Helpers
// =============================================================================

// findCommand walks the tree from root and returns the command matching
// the given space-separated path (e.g. "usulnet recon scan start"). The
// first element must be the root's Name. Returns nil when not found.
func findCommand(root *cobra.Command, path string) *cobra.Command {
	parts := splitFields(path)
	if len(parts) == 0 || parts[0] != root.Name() {
		return nil
	}
	cmd := root
	for _, p := range parts[1:] {
		var next *cobra.Command
		for _, sub := range cmd.Commands() {
			if sub.Name() == p {
				next = sub
				break
			}
		}
		if next == nil {
			return nil
		}
		cmd = next
	}
	return cmd
}

func splitFields(s string) []string {
	var out []string
	current := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			continue
		}
		current += string(r)
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

// sameFunc compares two function values by their runtime function
// pointer. Function pointers are not comparable with == in Go, so we
// route through reflect.
func sameFunc(a, b func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// equalSorted compares two []string slices after sorting copies of each.
// The completion order is not load-bearing for the static enums.
func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}

// withReconClientEnv overrides reconAPIURL / reconAPIToken (and the
// fallback env vars) for the duration of the test, then restores them.
// Used by every dynamic completer test so the completer hits the
// httptest server rather than a real network endpoint.
func withReconClientEnv(t *testing.T, url, token string) {
	t.Helper()
	origURL, origTok := reconAPIURL, reconAPIToken
	origEnvURL, hadEnvURL := os.LookupEnv("USULNET_API_URL")
	origEnvTok, hadEnvTok := os.LookupEnv("USULNET_API_TOKEN")
	reconAPIURL = url
	reconAPIToken = token
	t.Setenv("USULNET_API_URL", "")
	t.Setenv("USULNET_API_TOKEN", "")
	t.Cleanup(func() {
		reconAPIURL = origURL
		reconAPIToken = origTok
		if hadEnvURL {
			_ = os.Setenv("USULNET_API_URL", origEnvURL)
		} else {
			_ = os.Unsetenv("USULNET_API_URL")
		}
		if hadEnvTok {
			_ = os.Setenv("USULNET_API_TOKEN", origEnvTok)
		} else {
			_ = os.Unsetenv("USULNET_API_TOKEN")
		}
	})
}
