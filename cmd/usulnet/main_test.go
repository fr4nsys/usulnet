// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestRootCmdSilencesErrorsAndUsage pins the P5 behavior: cobra's default
// is to dump the full help text after any RunE error and to print "Error: ..."
// itself. The root error handler in main() owns that formatting, so both
// silencers must remain set.
func TestRootCmdSilencesErrorsAndUsage(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("rootCmd.SilenceUsage must be true — operator errors should not dump full help text")
	}
	if !rootCmd.SilenceErrors {
		t.Error("rootCmd.SilenceErrors must be true — main() handles error formatting")
	}
}

// TestVersionCmdUsesRunE pins the C2 behavior: every leaf subcommand uses
// RunE so the root error handler can propagate failures. The previous
// Run-only version command silently swallowed any error returned by
// app.PrintVersion (the typed return added in this PR is otherwise unused).
func TestVersionCmdUsesRunE(t *testing.T) {
	if versionCmd.RunE == nil {
		t.Error("versionCmd must declare RunE (not Run) so errors propagate to main()'s error handler")
	}
	if versionCmd.Run != nil {
		t.Error("versionCmd must not declare both Run and RunE — RunE is the contract")
	}
}

// TestParentCommandsPrintHelpOnBareInvocation walks the command tree and
// asserts that every parent (a command with subcommands) declares
//
//	Args: cobra.NoArgs
//	Run: ... calling cmd.Help() ...
//
// so `usulnet <parent>` with no further args prints the parent's help and
// exits 0. This is the P6 contract for the audit's quick-wins plan.
//
// The serve command is treated as a leaf (it has no subcommands) and is
// skipped by walkParents.
func TestParentCommandsPrintHelpOnBareInvocation(t *testing.T) {
	parents := collectParents(rootCmd)
	// Sanity: the audit lists nine parents below rootCmd. If the count
	// changes, the test author has new ground to cover (or to exclude).
	// Kept lex-sorted because the assertion compares against
	// sortedCopy(gotNames). Adding a new top-level parent: insert it
	// here in lex position.
	wantNames := []string{
		"admin", "backups", "config", "containers", "contexts",
		"findings", "hosts", "images", "meta", "migrate",
		"profile", "recon", "scan", "stacks", "target",
	}
	gotNames := make([]string, 0, len(parents))
	for _, p := range parents {
		gotNames = append(gotNames, p.Name())
	}
	if !reflect.DeepEqual(sortedCopy(gotNames), wantNames) {
		t.Errorf("parent command set drifted: got %v, want %v", gotNames, wantNames)
	}

	for _, p := range parents {
		t.Run(p.CommandPath(), func(t *testing.T) {
			if p.Args == nil {
				t.Error("parent must declare Args: cobra.NoArgs")
			}
			if p.Run == nil && p.RunE == nil {
				t.Fatal("parent must declare a Run that calls cmd.Help()")
			}

			// Functional: invoking the parent with no args must produce a
			// non-empty help string and exit cleanly. We capture stdout
			// to verify "Usage:" appears (cobra's standard help marker).
			buf := &bytes.Buffer{}
			resetCobraFlags(rootCmd)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(strings.Fields(p.CommandPath()[len("usulnet "):]))
			t.Cleanup(func() {
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				rootCmd.SetArgs(nil)
				resetCobraFlags(rootCmd)
			})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("bare %q should exit 0, got %v", p.CommandPath(), err)
			}
			if !strings.Contains(buf.String(), "Usage:") {
				t.Errorf("bare %q did not print help; got: %q", p.CommandPath(), buf.String())
			}
		})
	}
}

// collectParents walks the command tree rooted at c and returns every
// non-root command that has at least one subcommand. rootCmd itself is
// excluded because the audit scope (P6) targets the second tier and
// below. Cobra's auto-generated `completion` subtree is also excluded:
// it is added lazily on the first Execute() call (see Command.initDefaultCompletionCmd),
// so test ordering can leak it into the walker after an earlier test
// has invoked the root.
func collectParents(c *cobra.Command) []*cobra.Command {
	cobraBuiltins := map[string]bool{
		"help":       true,
		"completion": true,
	}
	var out []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(node *cobra.Command) {
		for _, sub := range node.Commands() {
			if cobraBuiltins[sub.Name()] {
				continue
			}
			if sub.HasSubCommands() {
				out = append(out, sub)
			}
			walk(sub)
		}
	}
	walk(c)
	return out
}

// collectLeaves walks the command tree rooted at c and returns every
// leaf — a command with no subcommands that is operator-callable
// (i.e. it carries a Run or RunE).
//
// Cobra's auto-generated helpers (`help`, `completion`, and the four
// `completion <shell>` shells under it) are skipped: they are framework
// boilerplate, not application surface, and Cobra ships its own help
// text for them. Same applies to anything marked Hidden.
func collectLeaves(c *cobra.Command) []*cobra.Command {
	cobraBuiltins := map[string]bool{
		"help":       true,
		"completion": true,
	}
	var out []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(node *cobra.Command) {
		for _, sub := range node.Commands() {
			if sub.Hidden {
				continue
			}
			if cobraBuiltins[sub.Name()] {
				// Cobra-generated subtree — skip the parent and all of
				// its children (the four `completion <shell>` leaves).
				continue
			}
			if sub.HasSubCommands() {
				walk(sub)
				continue
			}
			if sub.Run != nil || sub.RunE != nil {
				out = append(out, sub)
			}
		}
	}
	walk(c)
	return out
}

// TestCommandTree_LeafContract walks every operator-callable leaf and
// asserts the structural contract every leaf must satisfy: a RunE
// implementation (Run is forbidden so errors propagate to main()), a
// non-empty Long for `--help` output, a non-empty Example so operators
// have at least one copy-pasteable invocation, and every declared flag
// carrying a non-trivial description.
//
// This is the regression guard for the T1/T2 items in the session-19
// CLI audit: future subcommands cannot ship without the same operator
// affordances as the rest of the tree.
func TestCommandTree_LeafContract(t *testing.T) {
	leaves := collectLeaves(rootCmd)
	if len(leaves) == 0 {
		t.Fatal("collectLeaves returned 0 — walker is broken or every leaf is hidden")
	}

	for _, leaf := range leaves {
		t.Run(leaf.CommandPath(), func(t *testing.T) {
			if leaf.RunE == nil {
				t.Error("leaf must declare RunE so the root error handler can propagate failures")
			}
			if leaf.Run != nil {
				t.Error("leaf must not declare Run alongside RunE — RunE is the contract")
			}
			if strings.TrimSpace(leaf.Long) == "" {
				t.Error("leaf must declare a non-empty Long so `--help` carries operator-facing detail")
			}
			if strings.TrimSpace(leaf.Example) == "" {
				t.Error("leaf must declare a non-empty Example so operators have a copy-pasteable invocation")
			}
			assertFlagDescriptions(t, leaf)
		})
	}
}

// TestCommandTree_ParentContract walks every parent (a node with
// subcommands) and asserts the P6 audit contract: a non-empty Short,
// a non-empty Long, Args == cobra.NoArgs, and a Run that defers to
// cmd.Help() so `usulnet <parent>` with no further args prints the
// parent's help and exits 0.
//
// Parents do not need an Example — the helpful copy-pasteable
// invocations live on the leaves. They also do not need RunE (Run is
// fine here because cmd.Help() returns no error).
func TestCommandTree_ParentContract(t *testing.T) {
	parents := collectParents(rootCmd)
	if len(parents) == 0 {
		t.Fatal("collectParents returned 0 — every parent is hidden or the walker is broken")
	}

	for _, parent := range parents {
		t.Run(parent.CommandPath(), func(t *testing.T) {
			if strings.TrimSpace(parent.Short) == "" {
				t.Error("parent must declare a non-empty Short for parent-of-tree help listings")
			}
			if strings.TrimSpace(parent.Long) == "" {
				t.Error("parent must declare a non-empty Long for `--help` output")
			}
			if parent.Args == nil {
				t.Error("parent must declare Args so `usulnet <parent> garbage` does not silently succeed")
			}
			if parent.Run == nil && parent.RunE == nil {
				t.Error("parent must declare a Run that defers to cmd.Help() so bare invocation prints help")
			}
			assertFlagDescriptions(t, parent)
		})
	}
}

// assertFlagDescriptions fails when any flag on c (local or persistent)
// has a description shorter than 5 characters. The threshold matches the
// session-19 audit's "operator can read it" floor — anything shorter is
// effectively unlabelled. The check excludes Cobra's auto-generated
// `--help` flag (description "help for <cmd>" — Cobra owns the wording).
func assertFlagDescriptions(t *testing.T, c *cobra.Command) {
	t.Helper()
	const minDesc = 5

	check := func(scope string, flagset interface{ VisitAll(func(*pflag.Flag)) }) {
		flagset.VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			if utf8.RuneCountInString(strings.TrimSpace(f.Usage)) < minDesc {
				t.Errorf("%s flag --%s has description %q (need ≥ %d runes)",
					scope, f.Name, f.Usage, minDesc)
			}
		})
	}
	check("local", c.Flags())
	check("persistent", c.PersistentFlags())
}

// sortedCopy returns a sorted copy of s without mutating the input.
func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
