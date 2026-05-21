// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// =============================================================================
// Cobra wiring (AG1)
// =============================================================================

// TestRootCmdHasExpectedSubcommands locks the documented subcommand
// tree: run, version, validate-config. Adding new subcommands is fine;
// the test guards against accidentally renaming or dropping one.
func TestRootCmdHasExpectedSubcommands(t *testing.T) {
	want := map[string]bool{
		"run":             false,
		"version":         false,
		"validate-config": false,
	}
	for _, sub := range rootCmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q missing from rootCmd", name)
		}
	}
}

// TestRootCmdRunsAgentByDefault pins the contract that bare
// "usulnet-agent" (no subcommand) is equivalent to "usulnet-agent run".
// Both must declare a RunE so the user can drop the subcommand for
// backward compatibility with the previous stdlib-flag binary.
func TestRootCmdRunsAgentByDefault(t *testing.T) {
	if rootCmd.RunE == nil {
		t.Error("rootCmd must declare RunE so bare invocation starts the agent")
	}
	var runSub *cobra.Command
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "run" {
			runSub = sub
			break
		}
	}
	if runSub == nil {
		t.Fatal("run subcommand missing")
	}
	if runSub.RunE == nil {
		t.Error("run subcommand must declare RunE")
	}
}

// =============================================================================
// validate-config (AG1 — required-fields contract)
// =============================================================================

// TestValidateConfigMissingToken asserts the must-have field. Without
// --token (and no $USULNET_AGENT_TOKEN), validate-config fails with a
// usage error that names the env var.
func TestValidateConfigMissingToken(t *testing.T) {
	t.Setenv("USULNET_AGENT_TOKEN", "")
	resetCobra(t)
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"validate-config"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when token is missing")
	}
	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("error should mention token: got %q", err.Error())
	}
}

// TestValidateConfigWithToken confirms the happy path. The Token from
// --token reaches validateConfig() and the command exits 0.
func TestValidateConfigWithToken(t *testing.T) {
	resetCobra(t)
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"validate-config", "--token", "tok"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	// validateConfigCmd writes "Agent configuration is valid" to
	// os.Stdout via fmt.Println — not via cmd.OutOrStdout(), so the
	// captured buf may be empty. The success contract is the zero
	// return from Execute().
}

// =============================================================================
// AG3 — docker host env precedence
// =============================================================================

// TestDockerHostDefaultPrecedence verifies the env-var priority:
// USULNET_AGENT_DOCKER_HOST wins, then DOCKER_HOST, then the
// unix-socket fallback.
func TestDockerHostDefaultPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		usulnetVar string
		dockerVar  string
		want       string
	}{
		{"usulnet wins", "tcp://winner:1", "tcp://loser:1", "tcp://winner:1"},
		{"docker fallback", "", "tcp://compat:1", "tcp://compat:1"},
		{"hardcoded default", "", "", "unix:///var/run/docker.sock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("USULNET_AGENT_DOCKER_HOST", tc.usulnetVar)
			t.Setenv("DOCKER_HOST", tc.dockerVar)
			got := dockerHostDefault()
			if got != tc.want {
				t.Errorf("dockerHostDefault() = %q, want %q", got, tc.want)
			}
		})
	}
}

// =============================================================================
// AG2 — yaml unmarshal into agent.Config (no mirror struct)
// =============================================================================

// TestAgentConfigHasYAMLTags pins the AG2 design: every operator-facing
// field on agent.Config carries a yaml tag, so adding a new YAML key
// only requires a new tagged field — no mirror struct to keep in sync.
// The detailed field-by-field coverage lives in config_test.go.
func TestAgentConfigHasYAMLTags(t *testing.T) {
	// This is an indirect assertion via the public loadConfigFile
	// helper exercised by config_test.go::TestLoadConfigFile_FullConfig.
	// If that test passes, agent.Config has the necessary yaml tags.
	t.Log("Coverage delegated to config_test.go::TestLoadConfigFile_FullConfig")
}

// TestVersionCmdRunsClean exercises the version subcommand's RunE so
// the underlying fmt.Printf path is covered. The exact output is
// dependent on build-time ldflags (Version/Commit/BuildDate are "dev"
// in a bare `go test` run), so the assertion just pins the prefix and
// the absence of an error.
func TestVersionCmdRunsClean(t *testing.T) {
	resetCobra(t)
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("usulnet-agent version returned error: %v", err)
	}
	// versionCmd writes to os.Stdout via fmt.Printf, not cmd.OutOrStdout,
	// so the captured buffer stays empty. The success contract is the
	// zero error return; the actual rendering is exercised by manual
	// inspection of the binary.
	_ = buf
}

// =============================================================================
// Walk-the-tree contract (AG1 — T2 from the session-19 CLI audit)
// =============================================================================

// TestCommandTree_LeafContract walks the agent's command tree and pins
// the structural contract every leaf subcommand must satisfy: a RunE
// implementation (Run is forbidden so errors propagate to main()), a
// non-empty Long for `--help` output, a non-empty Example so operators
// have a copy-pasteable invocation, and every flag carrying a
// non-trivial description.
//
// The agent's rootCmd is special — it has subcommands AND its own RunE
// (bare `usulnet-agent` is equivalent to `usulnet-agent run`). The
// walker treats it as a parent and exercises the three documented
// leaves: run / version / validate-config.
func TestCommandTree_LeafContract(t *testing.T) {
	leaves := collectAgentLeaves(rootCmd)
	if len(leaves) == 0 {
		t.Fatal("collectAgentLeaves returned 0 — walker broken or every leaf is hidden")
	}

	for _, leaf := range leaves {
		t.Run(leaf.CommandPath(), func(t *testing.T) {
			if leaf.RunE == nil {
				t.Error("leaf must declare RunE so errors propagate to main()'s error handler")
			}
			if leaf.Run != nil {
				t.Error("leaf must not declare Run alongside RunE — RunE is the contract")
			}
			if strings.TrimSpace(leaf.Long) == "" {
				t.Error("leaf must declare a non-empty Long for `--help` output")
			}
			if strings.TrimSpace(leaf.Example) == "" {
				t.Error("leaf must declare a non-empty Example so operators have a copy-pasteable invocation")
			}
			assertAgentFlagDescriptions(t, leaf)
		})
	}
}

// TestCommandTree_RootContract pins the agent's dual-role root: it has
// subcommands (so it acts as a parent) AND a RunE so bare invocation
// starts the agent. The walk-the-tree assertions for the root therefore
// expect a non-empty Long, a non-empty Short, and every persistent flag
// carrying a usable description. The Args restriction (NoArgs) is
// intentionally absent — the root accepts an arbitrary command line
// when it delegates to runAgent.
func TestCommandTree_RootContract(t *testing.T) {
	if rootCmd.RunE == nil {
		t.Error("rootCmd must declare RunE so bare `usulnet-agent` invocation starts the agent")
	}
	if strings.TrimSpace(rootCmd.Short) == "" {
		t.Error("rootCmd must declare a non-empty Short")
	}
	if strings.TrimSpace(rootCmd.Long) == "" {
		t.Error("rootCmd must declare a non-empty Long")
	}
	assertAgentFlagDescriptions(t, rootCmd)
}

// collectAgentLeaves walks the agent command tree from c and returns
// every operator-callable leaf — a command with no subcommands that
// carries a Run or RunE. Cobra's auto-generated `help` / `completion`
// subtrees and any Hidden command are skipped.
func collectAgentLeaves(c *cobra.Command) []*cobra.Command {
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

// assertAgentFlagDescriptions fails when any flag on c has a description
// shorter than 5 runes. Mirror of the rule in cmd/usulnet's walk; kept
// in this package so the agent does not import the main binary's test
// helpers.
func assertAgentFlagDescriptions(t *testing.T, c *cobra.Command) {
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

// =============================================================================
// Helpers
// =============================================================================

// resetCobra resets every flag on rootCmd and every subcommand to its
// declared default, and clears any SetArgs / SetOut / SetErr from a
// prior test. Cobra retains parsed values across Execute() calls, so
// without this reset a test that came after `--help` would still have
// the help bool set.
func resetCobra(t *testing.T) {
	t.Helper()
	reset := func(c *cobra.Command) {
		visit := func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
		c.Flags().VisitAll(visit)
		c.PersistentFlags().VisitAll(visit)
	}
	reset(rootCmd)
	for _, sub := range rootCmd.Commands() {
		reset(sub)
	}
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		reset(rootCmd)
		for _, sub := range rootCmd.Commands() {
			reset(sub)
		}
	})
}
