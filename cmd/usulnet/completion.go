// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"context"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/fr4nsys/usulnet/cmd/usulnet/internal/apiclient"
)

// completionTimeout caps every API call issued from a shell completion
// handler. Completions run synchronously during tab — a slow API call
// stalls the operator's shell. Two seconds is enough for the local
// server's list endpoints and short enough to fail quietly when the
// server is unreachable.
const completionTimeout = 2 * time.Second

// mustRegisterFlagCompletion panics when RegisterFlagCompletionFunc
// fails. The only failure mode is "no such flag", which is a typo at
// init time — the binary should not start in that state.
func mustRegisterFlagCompletion(cmd *cobra.Command, name string, fn func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
	if err := cmd.RegisterFlagCompletionFunc(name, fn); err != nil {
		panic("register completion for --" + name + " on " + cmd.CommandPath() + ": " + err.Error())
	}
}

// =============================================================================
// Static completers — enum flags whose values never depend on server state.
// Wired in via cobra.FixedCompletions from the relevant init() functions.
// =============================================================================

var (
	completeOutputFormats   = []string{"table", "json", "yaml"}
	completeServeModes      = []string{"standalone", "master", "agent"}
	completeServeComponents = []string{"api", "gateway", "scheduler"}
	completeReportFormats   = []string{"json", "csv", "pdf"}
	completeSeverityLevels  = []string{"info", "low", "medium", "high", "critical"}
	completeTargetTypes     = []string{"email", "phone", "username", "domain", "ip", "ip_range"}
)

// =============================================================================
// Dynamic completers — talk to the local API to enumerate resources.
//
// All of them follow the same contract:
//   - resolve the same apiclient the recon subcommands use (so --server /
//     --token / env overrides apply equally to completion)
//   - run the call under completionTimeout
//   - on any failure return NoFileComp so the shell does NOT fall through
//     to filename completion (which would be misleading for an ID slot)
// =============================================================================

// newCompletionClient builds an apiclient configured with a short timeout
// suitable for tab-completion. It uses the same --server / --token /
// $USULNET_API_URL / $USULNET_API_TOKEN resolution as the recon tree.
func newCompletionClient() (*apiclient.Client, error) {
	return apiclient.New(apiclient.Options{
		BaseURL: reconAPIURL,
		Token:   reconAPIToken,
		Timeout: completionTimeout,
	})
}

// completionContext derives a short-deadline context from cmd.Context(),
// falling back to context.Background() when the command has no parent
// context attached (cobra leaves it nil until the first Execute()
// — completion shells may invoke us before that path runs).
func completionContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, completionTimeout)
}

// completeReconTargetIDs lists target IDs for positionals that take a
// target-id. Each completion entry is formatted as "<id>\t<type>:<value>"
// so shells that render descriptions (bash, zsh, fish) display a
// human-friendly hint alongside the UUID.
func completeReconTargetIDs(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	client, err := newCompletionClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := completionContext(cmd)
	defer cancel()
	var targets []targetResponse
	if err := client.Do(ctx, http.MethodGet, "/api/v1/recon/targets", nil, &targets); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		desc := t.Type
		if t.Value != "" {
			desc = t.Type + ":" + t.Value
		}
		out = append(out, t.ID+"\t"+desc)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeReconScanIDs lists scan IDs for positionals that take a scan-id
// (status / cancel / report). Each entry is "<id>\t<status>" so the
// operator can spot a "running" scan among "completed" ones during
// completion.
func completeReconScanIDs(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	client, err := newCompletionClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := completionContext(cmd)
	defer cancel()
	var scans []scanResponse
	if err := client.Do(ctx, http.MethodGet, "/api/v1/recon/scans", nil, &scans); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(scans))
	for _, s := range scans {
		desc := s.Status
		if desc == "" {
			desc = "scan"
		}
		out = append(out, s.ID+"\t"+desc)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeReconProfileNames lists profile *names* (not UUIDs) — the recon
// tree accepts either, but names are far easier to type by hand. The
// description column is the profile's kind (built-in / custom / ...).
func completeReconProfileNames(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	client, err := newCompletionClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := completionContext(cmd)
	defer cancel()
	var profiles []profileResponse
	if err := client.Do(ctx, http.MethodGet, "/api/v1/recon/profiles", nil, &profiles); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(profiles))
	for _, p := range profiles {
		desc := p.Kind
		if desc == "" {
			desc = "profile"
		}
		out = append(out, p.Name+"\t"+desc)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeReconTargetAddArgs returns completions for the two positionals
// of `recon target add <type> <value>`. Position 0 is a fixed enum
// (target type); position 1 has no useful default — the operator types
// the literal identifier — so we suppress file completion there.
func completeReconTargetAddArgs(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return completeTargetTypes, cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}
