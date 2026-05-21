// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Host-side CLI client subcommands (v26.5.2 plan / session 03).
//
// These subcommands let an operator drive a remote usulnet installation
// from their laptop or a CI runner without `docker exec`. They reuse
// the same apiclient package that the existing `recon` and `meta`
// subcommands use; the new bits are:
//
//   1. Context store at ~/.config/usulnet/config.yaml so multiple
//      installations can be addressed by name.
//   2. Login (headless: --token only this iteration; a web callback
//      flow is a follow-up).
//   3. Curated read-mostly subset of the API surface: containers,
//      images, stacks, hosts, backups, version.
//
// Exit codes match the existing recon / meta tree (0/2/64/70/71/72)
// via the same usageError + apiclient typed errors path.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/fr4nsys/usulnet/cmd/usulnet/internal/apiclient"
	config "github.com/fr4nsys/usulnet/cmd/usulnet/internal/clientconfig"
)

// =============================================================================
// `usulnet contexts ...`
// =============================================================================

var contextsCmd = &cobra.Command{
	Use:   "contexts",
	Short: "Manage saved API endpoints (installations)",
	Long: `Manage the named "contexts" that store URL + token + TLS-verify
preference for each usulnet installation you administer.

Context resolution order at command time:
  1. $USULNET_CONTEXT env var.
  2. default_context: line in ~/.config/usulnet/config.yaml.
  3. The single context, if exactly one is configured.

See also: usulnet login --help, docs/cli.md.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var contextsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured contexts (default marked with *)",
	Long: `Print every context saved in ~/.config/usulnet/config.yaml.
The default context is marked with a * in the DEFAULT column.`,
	Example: `  usulnet contexts list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := config.Load()
		if err != nil {
			return err
		}
		if len(f.Contexts) == 0 {
			fmt.Println("No contexts configured. Run `usulnet login <url> --token <key>` to add one.")
			return nil
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "NAME\tDEFAULT\tURL\tINSECURE")
		for name, c := range f.Contexts {
			star := ""
			if f.DefaultContext == name {
				star = "*"
			}
			ins := ""
			if c.Insecure {
				ins = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, star, c.URL, ins)
		}
		return tw.Flush()
	},
}

var contextsUseCmd = &cobra.Command{
	Use:   "use NAME",
	Short: "Set NAME as the default context",
	Long: `Change the default_context: line in
~/.config/usulnet/config.yaml so future subcommands use NAME
unless $USULNET_CONTEXT overrides it at command time.`,
	Example: `  usulnet contexts use prod`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := config.Load()
		if err != nil {
			return err
		}
		if _, ok := f.Contexts[args[0]]; !ok {
			return &usageError{msg: fmt.Sprintf("context %q does not exist", args[0])}
		}
		f.DefaultContext = args[0]
		if err := config.Save(f); err != nil {
			return err
		}
		fmt.Printf("default context set to %q\n", args[0])
		return nil
	},
}

var contextsRmCmd = &cobra.Command{
	Use:   "rm NAME",
	Short: "Remove a configured context",
	Long: `Delete the named context from the config file. If the
removed context was the default, the default is cleared and the
user must run "usulnet contexts use NAME" to pick a new default
(or set $USULNET_CONTEXT per command).`,
	Example: `  usulnet contexts rm staging`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := config.Load()
		if err != nil {
			return err
		}
		if err := f.Remove(args[0]); err != nil {
			return &usageError{msg: err.Error()}
		}
		if err := config.Save(f); err != nil {
			return err
		}
		fmt.Printf("removed context %q\n", args[0])
		return nil
	},
}

// =============================================================================
// `usulnet login <url> [--token TOKEN] [--name NAME] [--insecure]`
// =============================================================================

var (
	loginName     string
	loginToken    string
	loginInsecure bool
)

var loginCmd = &cobra.Command{
	Use:   "login URL",
	Short: "Save credentials for a usulnet installation",
	Long: `Save the URL + token for a remote usulnet installation. Future
subcommands will use this context unless --context or
$USULNET_CONTEXT overrides it.

This release ships the headless --token flow only; a browser-callback
flow ("usulnet login URL" with no --token, opens browser) is on the
v26.5.3 plan. For now, mint an API key in the web UI at
Settings > API Keys, then run:

  usulnet login https://prod.example.com:7443 --token <key>

For local installs with self-signed TLS, pass --insecure to skip
certificate verification:

  usulnet login https://localhost:7443 --token <key> --insecure

The token is stored at ~/.config/usulnet/config.yaml with mode 0600.`,
	Example: `  usulnet login https://prod.example.com:7443 --token K6L...
  usulnet login https://localhost:7443 --token K6L... --insecure --name local
  USULNET_CONTEXT=local usulnet containers ls`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := args[0]
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return &usageError{msg: fmt.Sprintf("invalid URL %q: must include scheme + host", raw)}
		}
		if loginToken == "" {
			return &usageError{msg: "this iteration requires --token; the browser flow is a v26.5.3 follow-up"}
		}
		name := loginName
		if name == "" {
			name = u.Hostname()
			if name == "localhost" {
				name = "local"
			}
		}

		f, err := config.Load()
		if err != nil {
			return err
		}
		f.Set(name, config.Context{
			URL:      strings.TrimRight(raw, "/"),
			Token:    loginToken,
			Insecure: loginInsecure,
		})
		if err := config.Save(f); err != nil {
			return err
		}
		fmt.Printf("saved context %q (default: %v)\n", name, f.DefaultContext == name)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout [NAME]",
	Short: "Remove a stored context (defaults to the active one)",
	Long: `Logout deletes a saved context — same as "usulnet contexts
rm NAME" but with sensible defaults. With no argument, the active
context is removed.`,
	Example: `  usulnet logout
  usulnet logout staging`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := config.Load()
		if err != nil {
			return err
		}
		var target string
		if len(args) == 1 {
			target = args[0]
		} else {
			name, _, err := f.Active()
			if err != nil {
				return &usageError{msg: err.Error()}
			}
			target = name
		}
		if err := f.Remove(target); err != nil {
			return &usageError{msg: err.Error()}
		}
		if err := config.Save(f); err != nil {
			return err
		}
		fmt.Printf("logged out of %q\n", target)
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the active context and the authenticated user",
	Long: `Print the active context's name + URL, then hit
/api/v1/auth/me to confirm the saved token is still valid and
show the authenticated user's id / email / role. Useful as a
1-liner connectivity check before deeper commands.`,
	Example: `  usulnet whoami
  usulnet --json whoami`,
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := config.Load()
		if err != nil {
			return err
		}
		name, ctx, err := f.Active()
		if err != nil {
			return &usageError{msg: err.Error()}
		}
		client, err := clientFor(ctx)
		if err != nil {
			return err
		}
		var resp struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Role     string `json:"role"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/auth/me", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			b, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("Context:  %s\n", name)
		fmt.Printf("URL:      %s\n", ctx.URL)
		fmt.Printf("User:     %s (%s)\n", resp.Username, resp.ID)
		fmt.Printf("Email:    %s\n", resp.Email)
		fmt.Printf("Role:     %s\n", resp.Role)
		return nil
	},
}

// =============================================================================
// `usulnet containers ls`
// =============================================================================

var containersCmd = &cobra.Command{
	Use:   "containers",
	Short: "Inspect containers on the active installation",
	Long: `Inspect containers on the active installation. Reads the
selected context (see "usulnet contexts list") and talks to its
/api/v1/containers endpoint over HTTPS. Read-only this release;
mutating ops (start/stop/restart/exec) are a v26.5.3 follow-up.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var containersListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List containers across all attached hosts",
	Long: `Walk every attached host and print one row per container
(ID truncated to 12 chars to match docker CLI output).`,
	Example: `  usulnet containers ls
  usulnet --json containers ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := activeClient()
		if err != nil {
			return err
		}
		var resp []struct {
			ID     string   `json:"id"`
			Name   string   `json:"name"`
			Image  string   `json:"image"`
			Status string   `json:"status"`
			State  string   `json:"state"`
			Ports  []string `json:"ports"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/containers", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(resp)
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "ID\tNAME\tIMAGE\tSTATE\tSTATUS")
		for _, c := range resp {
			id := c.ID
			if len(id) > 12 {
				id = id[:12]
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", id, c.Name, c.Image, c.State, c.Status)
		}
		return tw.Flush()
	},
}

// =============================================================================
// `usulnet images ls` + `usulnet stacks ls` + `usulnet backups ls`
// (read-only; mutating ops via stacks/deploy are deferred to v26.5.3)
// =============================================================================

var imagesCmd = &cobra.Command{
	Use:   "images",
	Short: "List images on the active installation",
	Long: `Inspect images on the active installation. Walks every
attached host and prints the local image cache. Read-only this
release.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var imagesListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List images across all attached hosts",
	Long: `Fetch /api/v1/hosts then /api/v1/images/{hostID} per host
and print one row per image (ID truncated to 12 chars).`,
	Example: `  usulnet images ls
  usulnet --json images ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := activeClient()
		if err != nil {
			return err
		}
		var hosts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/hosts", nil, &hosts); err != nil {
			return err
		}
		type row struct {
			Host, ID, Repo, Tag, Size string
		}
		var rows []row
		for _, h := range hosts {
			var imgs []struct {
				ID      string `json:"id"`
				RepoTag string `json:"repo_tag"`
				Size    int64  `json:"size"`
			}
			if err := client.Do(c, "GET", "/api/v1/images/"+h.ID, nil, &imgs); err != nil {
				continue
			}
			for _, im := range imgs {
				id := im.ID
				if len(id) > 12 {
					id = id[:12]
				}
				repo, tag := splitRepoTag(im.RepoTag)
				rows = append(rows, row{h.Name, id, repo, tag, fmtSize(im.Size)})
			}
		}
		if outputFormat == "json" {
			return printJSON(rows)
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "HOST\tIMAGE ID\tREPOSITORY\tTAG\tSIZE")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Host, r.ID, r.Repo, r.Tag, r.Size)
		}
		return tw.Flush()
	},
}

var stacksCmd = &cobra.Command{
	Use:   "stacks",
	Short: "Inspect deployed stacks",
	Long: `List stacks deployed across the active installation. Deploy /
remove operations are a v26.5.3 follow-up.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var stacksListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List deployed stacks",
	Long: `Print every stack deployed via the active installation,
with host + current status.`,
	Example: `  usulnet stacks ls
  usulnet --json stacks ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := activeClient()
		if err != nil {
			return err
		}
		var resp []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Status   string `json:"status"`
			HostName string `json:"host_name"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/stacks", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(resp)
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "NAME\tHOST\tSTATUS\tID")
		for _, s := range resp {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Name, s.HostName, s.Status, s.ID)
		}
		return tw.Flush()
	},
}

var backupsCmd = &cobra.Command{
	Use:   "backups",
	Short: "Inspect backups",
	Long: `List recent backups across the active installation.
Restore / verify-trigger operations are a v26.5.3 follow-up.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var backupsListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List recent backups",
	Long: `Show the most recent backups on the active installation
across every host.`,
	Example: `  usulnet backups ls
  usulnet --json backups ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := activeClient()
		if err != nil {
			return err
		}
		var resp []struct {
			ID         string `json:"id"`
			TargetName string `json:"target_name"`
			Type       string `json:"type"`
			Status     string `json:"status"`
			SizeBytes  int64  `json:"size_bytes"`
			CreatedAt  string `json:"created_at"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/backups", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(resp)
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "ID\tTARGET\tTYPE\tSTATUS\tSIZE\tCREATED")
		for _, b := range resp {
			id := b.ID
			if len(id) > 12 {
				id = id[:12]
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				id, b.TargetName, b.Type, b.Status, fmtSize(b.SizeBytes), b.CreatedAt)
		}
		return tw.Flush()
	},
}

// =============================================================================
// `usulnet hosts ls`
// =============================================================================

var hostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "Inspect attached Docker hosts",
	Long: `Inspect Docker hosts attached to the active installation.
Includes the local host (always present) and every agent
registered via "usulnet host add ..." in the web UI.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, _ []string) { _ = cmd.Help() },
}

var hostsListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List hosts in the active installation",
	Long: `Print every Docker host the active installation manages —
the local host plus every agent. Status reflects the last
heartbeat from the host service.`,
	Example: `  usulnet hosts ls
  usulnet --json hosts ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := activeClient()
		if err != nil {
			return err
		}
		var resp []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			Status        string `json:"status"`
			DockerVersion string `json:"docker_version"`
			OSType        string `json:"os_type"`
			Architecture  string `json:"architecture"`
		}
		c, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := client.Do(c, "GET", "/api/v1/hosts", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(resp)
		}
		tw := newTabWriter()
		fmt.Fprintln(tw, "NAME\tSTATUS\tOS/ARCH\tDOCKER\tID")
		for _, h := range resp {
			fmt.Fprintf(tw, "%s\t%s\t%s/%s\t%s\t%s\n",
				h.Name, h.Status, h.OSType, h.Architecture, h.DockerVersion, h.ID)
		}
		return tw.Flush()
	},
}

// =============================================================================
// Wiring
// =============================================================================

func init() {
	loginCmd.Flags().StringVar(&loginName, "name", "", "name for this context (default: derived from URL hostname)")
	loginCmd.Flags().StringVar(&loginToken, "token", "", "API token (required for this iteration; browser flow is v26.5.3)")
	loginCmd.Flags().BoolVar(&loginInsecure, "insecure", false, "skip TLS certificate verification (use for self-signed certs)")

	contextsCmd.AddCommand(contextsListCmd, contextsUseCmd, contextsRmCmd)
	containersCmd.AddCommand(containersListCmd)
	imagesCmd.AddCommand(imagesListCmd)
	stacksCmd.AddCommand(stacksListCmd)
	backupsCmd.AddCommand(backupsListCmd)
	hostsCmd.AddCommand(hostsListCmd)

	rootCmd.AddCommand(
		contextsCmd,
		loginCmd,
		logoutCmd,
		whoamiCmd,
		containersCmd,
		imagesCmd,
		stacksCmd,
		backupsCmd,
		hostsCmd,
	)
}

// =============================================================================
// Helpers
// =============================================================================

// activeClient resolves a client for the currently active context.
// Used by every read subcommand.
func activeClient() (*apiclient.Client, error) {
	f, err := config.Load()
	if err != nil {
		return nil, err
	}
	_, ctx, err := f.Active()
	if err != nil {
		return nil, &usageError{msg: err.Error()}
	}
	return clientFor(ctx)
}

func clientFor(ctx *config.Context) (*apiclient.Client, error) {
	opts := apiclient.Options{
		BaseURL: ctx.URL,
		Token:   ctx.Token,
	}
	if ctx.Insecure {
		// The apiclient honours USULNET_API_INSECURE; we set it
		// per-call by patching the HTTP transport after construction.
		c, err := apiclient.New(opts)
		if err != nil {
			return nil, err
		}
		setInsecureTransport(c)
		return c, nil
	}
	return apiclient.New(opts)
}

// setInsecureTransport patches the client's HTTP transport to skip
// TLS verification. Used when a context was saved with --insecure
// (the only safe place for self-signed certs on local installs).
func setInsecureTransport(c *apiclient.Client) {
	hc := c.HTTPClient()
	hc.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via --insecure
	}
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}

func splitRepoTag(rt string) (string, string) {
	if rt == "" {
		return "<none>", "<none>"
	}
	if i := strings.LastIndex(rt, ":"); i > 0 {
		return rt[:i], rt[i+1:]
	}
	return rt, "latest"
}

func fmtSize(n int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
