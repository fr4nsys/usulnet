// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// Exit codes used by the recon + meta subcommand trees.
//
// docs/recon.md §8 specifies:
//   0  success
//   2  per-file failure (full report is still printed)
//   64 argument error
//   >=70 infrastructure error
// =============================================================================

const (
	exitOK              = 0
	exitPerFileFailures = 2
	exitUsage           = 64
	exitInfra           = 70
	exitServerUnreach   = 71
	exitAuth            = 72
)

// usageError is returned by RunE when the user supplied bad arguments. The
// rootCmd wrapper translates it to exit code 64.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// infraError signals an unrecoverable infrastructure failure (server
// unreachable, Docker missing, etc.) and maps to exit codes in the 70+ range.
type infraError struct {
	msg  string
	code int
}

func (e *infraError) Error() string { return e.msg }

// =============================================================================
// Output handling — shared by every recon / meta subcommand.
// =============================================================================

// outputFormat is the value of the global --output flag. Default is "table".
var outputFormat string

// validateOutputFormat returns a usageError if the format isn't supported.
func validateOutputFormat() error {
	switch strings.ToLower(outputFormat) {
	case "", "table", "json", "yaml":
		return nil
	}
	return &usageError{msg: fmt.Sprintf("invalid --output %q (want table|json|yaml)", outputFormat)}
}

// tableRow is one row in a table-formatted output. The first slice is the
// header.
type tableRow []string

// writeOutput serializes `data` to the cobra command's stdout using the
// current --output format. table rendering requires the caller to supply
// rows (data must be of type [][]string, with the header as the first row).
//
// For json and yaml, `data` is serialized verbatim.
func writeOutput(cmd *cobra.Command, data any) error {
	w := cmd.OutOrStdout()
	switch strings.ToLower(outputFormat) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	case "yaml":
		b, err := yaml.Marshal(data)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	default:
		// table
		rows, ok := data.([]tableRow)
		if !ok {
			// Fall back to JSON when caller hasn't built rows for table mode.
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(data)
		}
		return writeTable(w, rows)
	}
}

// writeTable renders rows via text/tabwriter. The first row is the header.
// Empty input is a no-op.
func writeTable(w io.Writer, rows []tableRow) error {
	if len(rows) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// =============================================================================
// API client — a deliberately minimal HTTP client for /api/v1/recon and
// /api/v1/metadata. No existing client lives in internal/api/client, so this
// CLI builds one in-process; it reads $USULNET_API_URL and $USULNET_API_TOKEN
// (matching the convention adopted by every other usulnet CLI integration —
// see docs/v26.5/technical-notes.md "CLI conventions").
// =============================================================================

// apiClient wraps the local server's HTTP API.
type apiClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

// apiClientOptions are constructor options for apiClient. Empty fields are
// resolved from $USULNET_API_URL and $USULNET_API_TOKEN.
type apiClientOptions struct {
	BaseURL string
	Token   string
	Timeout time.Duration
}

// newAPIClient resolves connection info from opts then env, validating that
// at least a base URL is configured.
func newAPIClient(opts apiClientOptions) (*apiClient, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = os.Getenv("USULNET_API_URL")
	}
	if opts.Token == "" {
		opts.Token = os.Getenv("USULNET_API_TOKEN")
	}
	if opts.BaseURL == "" {
		return nil, &infraError{
			msg:  "no API URL configured: set --server or $USULNET_API_URL",
			code: exitServerUnreach,
		}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	return &apiClient{
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		token:   opts.Token,
		hc:      &http.Client{Timeout: opts.Timeout},
	}, nil
}

// do executes a JSON request and decodes the response into `out` when non-nil.
// Non-2xx responses are surfaced as an error containing the HTTP status and a
// truncated body.
func (c *apiClient) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return &infraError{msg: fmt.Sprintf("api request: %v", err), code: exitServerUnreach}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &infraError{
			msg:  fmt.Sprintf("api %s %s: %s", method, path, resp.Status),
			code: exitAuth,
		}
	}
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("api %s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(buf))
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// stream issues a GET that consumes a text/event-stream response, invoking
// onEvent for each parsed SSE event until the context is canceled or the
// stream closes.
func (c *apiClient) stream(ctx context.Context, path string, onEvent func(event, data string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	hc := &http.Client{Timeout: 0} // SSE keeps the connection open.
	resp, err := hc.Do(req)
	if err != nil {
		return &infraError{msg: fmt.Sprintf("api stream: %v", err), code: exitServerUnreach}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("api stream %s: %s", path, resp.Status)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if data != "" {
				onEvent(event, data)
			}
			event, data = "", ""
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if data != "" {
				data += "\n"
			}
			data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
		// Lines starting with ":" are SSE comments / heartbeats; they
		// match none of the cases above and are silently ignored.
	}
	return scanner.Err()
}

// =============================================================================
// DTOs — kept in sync with internal/api/handlers/recon.go response shapes.
// Only the fields the CLI displays are decoded.
// =============================================================================

type targetResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at"`
}

type ownershipProofResponse struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	Method     string `json:"method"`
	Status     string `json:"status"`
	Challenge  string `json:"challenge,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

type profileResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Kind        string   `json:"kind"`
	TargetTypes []string `json:"target_types"`
}

type scanResponse struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	ProfileID  string `json:"profile_id"`
	Status     string `json:"status"`
	Engine     string `json:"engine,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type findingResponse struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	TargetID string `json:"target_id"`
	Module   string `json:"module"`
	Severity string `json:"severity"`
	Value    string `json:"value"`
	Source   string `json:"source,omitempty"`
	LastSeen string `json:"last_seen"`
}

// =============================================================================
// Cobra command definitions
// =============================================================================

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "OSINT / privacy reconnaissance against owned targets",
	Long: `Manage recon targets, profiles, scans, and findings.

Every recon command talks to the running usulnet server over the
local API. Configure the server via --server or $USULNET_API_URL,
and authenticate via $USULNET_API_TOKEN.`,
}

// flags shared by recon
var (
	reconAPIURL   string
	reconAPIToken string
)

// scan start flags
var (
	scanStartProfile string
	scanStartWatch   bool
)

// findings list flags
var (
	findingsTarget   string
	findingsSeverity string
)

// scan report flags
var scanReportFormat string

// -------------------------- recon target -------------------------------------

var reconTargetCmd = &cobra.Command{
	Use:   "target",
	Short: "Manage recon targets",
}

var reconTargetAddCmd = &cobra.Command{
	Use:   "add <type> <value>",
	Short: "Create a recon target (email|phone|username|domain|ip|ip_range)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		body := map[string]string{"type": args[0], "value": args[1]}
		var resp targetResponse
		if err := client.do(cmd.Context(), http.MethodPost, "/api/v1/recon/targets", body, &resp); err != nil {
			return err
		}
		return writeOutput(cmd, targetRows([]targetResponse{resp}, true))
	},
}

var reconTargetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recon targets",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []targetResponse
		if err := client.do(cmd.Context(), http.MethodGet, "/api/v1/recon/targets", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, resp)
		}
		return writeOutput(cmd, targetRows(resp, true))
	},
}

var reconTargetVerifyCmd = &cobra.Command{
	Use:   "verify <id>",
	Short: "Start ownership verification (uses rdap_match by default)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		body := map[string]string{"method": "rdap_match"}
		var resp ownershipProofResponse
		err = client.do(cmd.Context(),
			http.MethodPost,
			"/api/v1/recon/targets/"+url.PathEscape(args[0])+"/ownership/verify",
			body, &resp)
		if err != nil {
			return err
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, resp)
		}
		rows := []tableRow{
			{"ID", "TARGET", "METHOD", "STATUS", "VERIFIED_AT"},
			{resp.ID, resp.TargetID, resp.Method, resp.Status, resp.VerifiedAt},
		}
		return writeOutput(cmd, rows)
	},
}

// -------------------------- recon profile ------------------------------------

var reconProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage recon profiles",
}

var reconProfileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recon profiles",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []profileResponse
		if err := client.do(cmd.Context(), http.MethodGet, "/api/v1/recon/profiles", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, resp)
		}
		rows := []tableRow{{"ID", "NAME", "KIND", "TARGET_TYPES"}}
		for _, p := range resp {
			rows = append(rows, tableRow{p.ID, p.Name, p.Kind, strings.Join(p.TargetTypes, ",")})
		}
		return writeOutput(cmd, rows)
	},
}

// -------------------------- recon scan ---------------------------------------

var reconScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Manage recon scans",
}

var reconScanStartCmd = &cobra.Command{
	Use:   "start <target-id>",
	Short: "Start a scan against a target using the named profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		if scanStartProfile == "" {
			return &usageError{msg: "missing --profile"}
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		profileID, err := resolveProfileID(cmd.Context(), client, scanStartProfile)
		if err != nil {
			return err
		}
		body := map[string]string{"target_id": args[0], "profile_id": profileID}
		var resp scanResponse
		if err := client.do(cmd.Context(), http.MethodPost, "/api/v1/recon/scans", body, &resp); err != nil {
			return err
		}
		if !scanStartWatch {
			if outputFormat == "json" || outputFormat == "yaml" {
				return writeOutput(cmd, resp)
			}
			return writeOutput(cmd, scanRows([]scanResponse{resp}, true))
		}
		// Watch: stream events from the scan. The endpoint is best-effort —
		// older servers without the SSE route still get a useful summary
		// printed above and then a clean exit.
		ctx := cmd.Context()
		path := "/api/v1/recon/scans/" + url.PathEscape(resp.ID) + "/events"
		err = client.stream(ctx, path, func(event, data string) {
			line := summarizeEvent(event, data)
			if line == "" {
				return
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		})
		if err != nil {
			// Treat stream errors as infrastructure problems but only
			// after the scan has been started.
			return &infraError{msg: fmt.Sprintf("watch: %v", err), code: exitServerUnreach}
		}
		return nil
	},
}

var reconScanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent scans",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []scanResponse
		if err := client.do(cmd.Context(), http.MethodGet, "/api/v1/recon/scans", nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, resp)
		}
		return writeOutput(cmd, scanRows(resp, true))
	},
}

var reconScanStatusCmd = &cobra.Command{
	Use:   "status <scan-id>",
	Short: "Show one scan's current status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp scanResponse
		path := "/api/v1/recon/scans/" + url.PathEscape(args[0])
		if err := client.do(cmd.Context(), http.MethodGet, path, nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, resp)
		}
		return writeOutput(cmd, scanRows([]scanResponse{resp}, true))
	},
}

var reconScanCancelCmd = &cobra.Command{
	Use:   "cancel <scan-id>",
	Short: "Cancel a running or queued scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := reconClient()
		if err != nil {
			return err
		}
		path := "/api/v1/recon/scans/" + url.PathEscape(args[0])
		if err := client.do(cmd.Context(), http.MethodDelete, path, nil, nil); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "canceled %s\n", args[0])
		return nil
	},
}

var reconScanReportCmd = &cobra.Command{
	Use:   "report <scan-id>",
	Short: "Download a scan report (--format json|csv|pdf, default json)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := strings.ToLower(scanReportFormat)
		if format == "" {
			format = "json"
		}
		switch format {
		case "json", "csv", "pdf":
		default:
			return &usageError{msg: fmt.Sprintf("invalid --format %q (want json|csv|pdf)", format)}
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		path := "/api/v1/recon/scans/" + url.PathEscape(args[0]) + "/report." + format
		req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, client.baseURL+path, nil)
		if err != nil {
			return err
		}
		if client.token != "" {
			req.Header.Set("Authorization", "Bearer "+client.token)
		}
		resp, err := client.hc.Do(req)
		if err != nil {
			return &infraError{msg: fmt.Sprintf("api request: %v", err), code: exitServerUnreach}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 400 {
			buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("api report: %s: %s", resp.Status, bytes.TrimSpace(buf))
		}
		_, err = io.Copy(cmd.OutOrStdout(), resp.Body)
		return err
	},
}

// -------------------------- recon findings -----------------------------------

var reconFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Inspect recon findings",
}

var reconFindingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings, optionally filtered by --target and --severity",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		// The findings endpoint is rooted under a scan; to list by target
		// (the documented CLI flag) we first list that target's scans, then
		// aggregate findings across them. When --target is absent the
		// command lists findings from the most recent scan only.
		scans, err := listScansForFilter(cmd.Context(), client, findingsTarget)
		if err != nil {
			return err
		}
		var out []findingResponse
		for _, s := range scans {
			path := "/api/v1/recon/scans/" + url.PathEscape(s.ID) + "/findings"
			if findingsSeverity != "" {
				path += "?severity=" + url.QueryEscape(findingsSeverity)
			}
			var batch []findingResponse
			if err := client.do(cmd.Context(), http.MethodGet, path, nil, &batch); err != nil {
				return err
			}
			out = append(out, batch...)
		}
		if outputFormat == "json" || outputFormat == "yaml" {
			return writeOutput(cmd, out)
		}
		rows := []tableRow{{"SEVERITY", "MODULE", "TARGET", "VALUE"}}
		for _, f := range out {
			rows = append(rows, tableRow{f.Severity, f.Module, f.TargetID, truncate(f.Value, 60)})
		}
		return writeOutput(cmd, rows)
	},
}

// =============================================================================
// Helpers
// =============================================================================

// reconClient resolves an apiClient from the recon-tree flags + env. It is
// re-resolved per command so unit tests can swap $USULNET_API_URL between
// invocations.
func reconClient() (*apiClient, error) {
	return newAPIClient(apiClientOptions{
		BaseURL: reconAPIURL,
		Token:   reconAPIToken,
	})
}

// resolveProfileID looks up a profile by name (the form the CLI accepts) and
// returns its UUID. Callers may also pass a raw UUID, in which case it is
// returned verbatim.
func resolveProfileID(ctx context.Context, client *apiClient, nameOrID string) (string, error) {
	if looksLikeUUID(nameOrID) {
		return nameOrID, nil
	}
	var profiles []profileResponse
	if err := client.do(ctx, http.MethodGet, "/api/v1/recon/profiles", nil, &profiles); err != nil {
		return "", err
	}
	for _, p := range profiles {
		if p.Name == nameOrID {
			return p.ID, nil
		}
	}
	return "", &usageError{msg: fmt.Sprintf("profile %q not found", nameOrID)}
}

// listScansForFilter returns the scans the findings command should aggregate
// over. When targetID is empty it returns the most recent scan (one item);
// otherwise every scan for that target.
func listScansForFilter(ctx context.Context, client *apiClient, targetID string) ([]scanResponse, error) {
	path := "/api/v1/recon/scans"
	if targetID != "" {
		path += "?target_id=" + url.QueryEscape(targetID)
	}
	var scans []scanResponse
	if err := client.do(ctx, http.MethodGet, path, nil, &scans); err != nil {
		return nil, err
	}
	if targetID == "" && len(scans) > 1 {
		scans = scans[:1]
	}
	return scans, nil
}

// looksLikeUUID is a cheap shape check; the server validates the value
// strictly so a false positive only triggers a 400.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func targetRows(items []targetResponse, header bool) []tableRow {
	rows := make([]tableRow, 0, len(items)+1)
	if header {
		rows = append(rows, tableRow{"ID", "TYPE", "VALUE", "LABEL", "CREATED"})
	}
	for _, t := range items {
		rows = append(rows, tableRow{t.ID, t.Type, t.Value, t.Label, t.CreatedAt})
	}
	return rows
}

func scanRows(items []scanResponse, header bool) []tableRow {
	rows := make([]tableRow, 0, len(items)+1)
	if header {
		rows = append(rows, tableRow{"ID", "TARGET", "PROFILE", "STATUS", "STARTED", "FINISHED"})
	}
	for _, s := range items {
		rows = append(rows, tableRow{s.ID, s.TargetID, s.ProfileID, s.Status, s.StartedAt, s.FinishedAt})
	}
	return rows
}

// summarizeEvent renders one SSE record as a one-line summary.
// The event payload is a JSON-encoded finding (the same shape the web UI
// renders); fields are accessed defensively so an unexpected payload still
// produces a useful line rather than crashing the watcher.
func summarizeEvent(event, data string) string {
	if data == "" {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return strings.TrimSpace(data)
	}
	sev, _ := payload["severity"].(string)
	mod, _ := payload["module"].(string)
	val, _ := payload["value"].(string)
	if sev == "" && mod == "" && val == "" {
		// Non-finding event (status update, heartbeat) — surface event name.
		if event != "" {
			return "[" + event + "]"
		}
		return ""
	}
	return fmt.Sprintf("%-8s %-24s %s", sev, mod, truncate(val, 40))
}

// truncate trims s to n runes, suffixing an ellipsis when shortened.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// =============================================================================
// Wiring into the root command + error→exit-code translation.
// =============================================================================

// reconLocalArtifactsDir is referenced by the meta subcommands (defined in
// meta.go) when constructing a local artifact store. Keeping the default
// here avoids duplicating the path constant between files.
const reconLocalArtifactsDir = "metadata-cli"

// hasReconError reports whether err — possibly wrapped — carries an
// exit-code hint. The wrapper in init() consults this and writes the
// matching exit code on usage / infra failures.
func hasReconError(err error) (code int, ok bool) {
	if err == nil {
		return 0, false
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return exitUsage, true
	}
	var ie *infraError
	if errors.As(err, &ie) {
		if ie.code == 0 {
			return exitInfra, true
		}
		return ie.code, true
	}
	return 0, false
}

// resolveTimeout converts an --timeout flag into a context deadline.
// Used by the local meta subcommands.
func resolveTimeout(ctx context.Context, raw string) (context.Context, context.CancelFunc, error) {
	if raw == "" {
		return ctx, func() {}, nil
	}
	// Accept either a duration (e.g. "30s") or a bare second count.
	if d, err := time.ParseDuration(raw); err == nil {
		ctx, cancel := context.WithTimeout(ctx, d)
		return ctx, cancel, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return ctx, func() {}, &usageError{msg: fmt.Sprintf("invalid --timeout %q", raw)}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(n)*time.Second)
	return ctx, cancel, nil
}

func init() {
	// Global flags shared by recon + meta.
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "table", "output format: table|json|yaml")

	// recon flags
	reconCmd.PersistentFlags().StringVar(&reconAPIURL, "server", "", "usulnet API URL (default $USULNET_API_URL)")
	reconCmd.PersistentFlags().StringVar(&reconAPIToken, "token", "", "API token (default $USULNET_API_TOKEN)")

	// scan start flags
	reconScanStartCmd.Flags().StringVar(&scanStartProfile, "profile", "", "profile name or UUID (required)")
	reconScanStartCmd.Flags().BoolVar(&scanStartWatch, "watch", false, "stream scan events to stdout")

	// scan report flags
	reconScanReportCmd.Flags().StringVar(&scanReportFormat, "format", "json", "report format: json|csv|pdf")

	// findings flags
	reconFindingsListCmd.Flags().StringVar(&findingsTarget, "target", "", "filter findings by target ID")
	reconFindingsListCmd.Flags().StringVar(&findingsSeverity, "severity", "", "filter findings by severity")

	// target tree
	reconTargetCmd.AddCommand(reconTargetAddCmd)
	reconTargetCmd.AddCommand(reconTargetListCmd)
	reconTargetCmd.AddCommand(reconTargetVerifyCmd)

	// profile tree
	reconProfileCmd.AddCommand(reconProfileListCmd)

	// scan tree
	reconScanCmd.AddCommand(reconScanStartCmd)
	reconScanCmd.AddCommand(reconScanListCmd)
	reconScanCmd.AddCommand(reconScanStatusCmd)
	reconScanCmd.AddCommand(reconScanCancelCmd)
	reconScanCmd.AddCommand(reconScanReportCmd)

	// findings tree
	reconFindingsCmd.AddCommand(reconFindingsListCmd)

	// recon root
	reconCmd.AddCommand(reconTargetCmd)
	reconCmd.AddCommand(reconProfileCmd)
	reconCmd.AddCommand(reconScanCmd)
	reconCmd.AddCommand(reconFindingsCmd)

	rootCmd.AddCommand(reconCmd)
}
