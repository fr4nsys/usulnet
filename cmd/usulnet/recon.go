// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/cmd/usulnet/internal/apiclient"
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
// outputJSONShortcut is the global --json flag; when true it forces
// outputFormat to "json" via the root command's PersistentPreRun.
// quietMode is the global --quiet flag; when true the CLI suppresses
// non-essential informational lines (e.g. "stripped: foo -> bar"). It
// does not affect errors or primary data output.
var (
	outputFormat       string
	outputJSONShortcut bool
	quietMode          bool
)

// validateOutputFormat returns a usageError if the format isn't supported.
func validateOutputFormat() error {
	switch strings.ToLower(outputFormat) {
	case "", "table", "json", "yaml":
		return nil
	}
	return &usageError{msg: fmt.Sprintf("invalid --output %q (want table|json|yaml)", outputFormat)}
}

// resolveOutputFlags must be called from a PersistentPreRun on rootCmd. It
// applies the --json convenience flag (forcing --output to "json") and
// validates the resolved format. Centralized here so the precedence —
// --json wins over an explicit --output — is in exactly one place.
func resolveOutputFlags() error {
	if outputJSONShortcut {
		outputFormat = "json"
	}
	return validateOutputFormat()
}

// infof writes an informational line to the command's stdout, unless
// --quiet is set. Use for non-essential success summaries (e.g.
// "stripped: foo -> bar"). Errors and primary data output must NOT
// route through infof — they are always emitted regardless of --quiet.
func infof(cmd *cobra.Command, format string, args ...any) {
	if quietMode {
		return
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), format, args...)
}

// tableRow is one row in a table-formatted output. The first slice is the
// header.
type tableRow []string

// writeView serializes a result using the current --output format.
//
//   - json/yaml: data is marshaled.
//   - table:     headers are printed on the first line, followed by each row
//     in rows. If headers is nil the function falls through to JSON to
//     preserve the existing behavior of callers that have nothing tabular
//     to render (e.g. a single-record API response with no headers built).
//
// writeView centralizes the json/yaml-vs-table branch so every list and
// record command can keep one path instead of two (the audit's H2 item).
func writeView(cmd *cobra.Command, data any, headers []string, rows [][]string) error {
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
		if headers == nil {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(data)
		}
		tableRows := make([]tableRow, 0, len(rows)+1)
		tableRows = append(tableRows, tableRow(headers))
		for _, row := range rows {
			tableRows = append(tableRows, tableRow(row))
		}
		return writeTable(w, tableRows)
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

// formatError renders err for stderr. In default mode the output is
// "usulnet: <message>"; under --output json the message is emitted as
// a structured record so scripts can parse it.
//
// This is the central H4 formatter — every error that escapes
// rootCmd.Execute() goes through here.
func formatError(err error) string {
	code, ok := metaExitCode(err)
	if !ok {
		code = 1
	}
	if strings.EqualFold(outputFormat, "json") {
		b, jerr := json.Marshal(struct {
			Error string `json:"error"`
			Code  int    `json:"code"`
		}{Error: err.Error(), Code: code})
		if jerr == nil {
			return string(b)
		}
	}
	return "usulnet: " + err.Error()
}

// =============================================================================
// API client wiring — the actual HTTP client lives in
// cmd/usulnet/internal/apiclient. The recon + meta trees both build a
// client via that package; this file just hosts the per-tree options and
// the error→exit-code translation (hasReconError below).
// =============================================================================

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
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
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
	Short: "Register, list, or verify ownership of recon targets",
	Long: `Manage the targets a recon scan can be aimed at.

  add <type> <value>     register a new target
  list                   show every target you own
  verify <id> <method>   prove ownership before a scan can start

Every recon scan requires a verified target. Ownership verification
runs out of band (DNS TXT, e-mail link, RDAP, admin-attest, or
self-assert) and is recorded in the audit log.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var reconTargetAddCmd = &cobra.Command{
	Use:   "add <type> <value>",
	Short: "Create a recon target (email|phone|username|domain|ip|ip_range)",
	Long: `Register a new recon target.

<type> must be one of: email, phone, username, domain, ip, ip_range.
<value> is the literal identifier (e.g. me@example.com, 192.168.1.1).

Once registered the target must be verified (recon target verify)
before scans can be queued against it.`,
	Example: `  usulnet recon target add email me@example.com
  usulnet recon target add domain example.com
  usulnet recon target add ip 192.168.1.1 --output json`,
	Args: cobra.ExactArgs(2),
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
		if err := client.Do(cmd.Context(), http.MethodPost, "/api/v1/recon/targets", body, &resp); err != nil {
			return err
		}
		return writeView(cmd, resp, targetTableHeaders, targetTableRows([]targetResponse{resp}))
	},
}

var reconTargetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recon targets",
	Long: `Print every registered recon target.

Default output is a table with ID, TYPE, VALUE, LABEL, and CREATED
columns. Use --output json|yaml for scripting.`,
	Example: `  usulnet recon target list
  usulnet recon target list --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []targetResponse
		if err := client.Do(cmd.Context(), http.MethodGet, "/api/v1/recon/targets", nil, &resp); err != nil {
			return err
		}
		return writeView(cmd, resp, targetTableHeaders, targetTableRows(resp))
	},
}

var reconTargetVerifyCmd = &cobra.Command{
	Use:   "verify <id>",
	Short: "Start ownership verification (uses rdap_match by default)",
	Long: `Begin ownership verification for the given target.

Currently rdap_match is the only supported method. The response
includes the proof ID and the current status (pending|verified|
failed). Scans cannot run against an unverified target.`,
	Example: `  usulnet recon target verify 11111111-1111-1111-1111-111111111111`,
	Args:    cobra.ExactArgs(1),
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
		err = client.Do(cmd.Context(),
			http.MethodPost,
			"/api/v1/recon/targets/"+url.PathEscape(args[0])+"/ownership/verify",
			body, &resp)
		if err != nil {
			return err
		}
		return writeView(cmd, resp,
			[]string{"ID", "TARGET", "METHOD", "STATUS", "VERIFIED_AT"},
			[][]string{{resp.ID, resp.TargetID, resp.Method, resp.Status, resp.VerifiedAt}},
		)
	},
}

// -------------------------- recon profile ------------------------------------

var reconProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "List the predefined scan profiles available to targets",
	Long: `Inspect the catalogue of scan profiles a target can be paired
with. Profiles bundle a curated module set and time budget so an
operator does not have to assemble one by hand.

  list   show every profile, built-in or user-defined

Built-in profiles are immutable. User-defined profiles are created
through the web UI; this subcommand is read-only.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var reconProfileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recon profiles",
	Long: `Print every available scan profile.

Output columns: ID, NAME, KIND, TARGET_TYPES (comma-separated).
Pass the profile name (or UUID) to "recon scan start --profile".`,
	Example: `  usulnet recon profile list
  usulnet recon profile list --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []profileResponse
		if err := client.Do(cmd.Context(), http.MethodGet, "/api/v1/recon/profiles", nil, &resp); err != nil {
			return err
		}
		rows := make([][]string, 0, len(resp))
		for _, p := range resp {
			rows = append(rows, []string{p.ID, p.Name, p.Kind, strings.Join(p.TargetTypes, ",")})
		}
		return writeView(cmd, resp,
			[]string{"ID", "NAME", "KIND", "TARGET_TYPES"},
			rows,
		)
	},
}

// -------------------------- recon scan ---------------------------------------

var reconScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start, list, watch, cancel, or download recon scan reports",
	Long: `Drive recon scans from the CLI. A scan pairs a verified
target with a profile and runs the configured modules in the
sandboxed recon container.

  start   queue a new scan for a target + profile
  list    show recent scans with state and progress
  status  poll one scan for live progress
  cancel  request cancellation of a running scan
  report  download a finished scan's report as JSON, CSV, or PDF

Scans cannot start until the target's ownership has been verified
and recon has been enabled by an admin.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var reconScanStartCmd = &cobra.Command{
	Use:   "start <target-id>",
	Short: "Start a scan against a target using the named profile",
	Long: `Queue a scan against the given target with the named profile.

--profile is required; pass either the profile name (see "recon
profile list") or a UUID.

Without --watch, the command returns once the scan is queued and
prints the scan record. With --watch the command streams scan
events from /api/v1/recon/scans/<id>/events until the scan
completes or the connection drops.`,
	Example: `  usulnet recon scan start 11111111-1111-1111-1111-111111111111 --profile default
  usulnet recon scan start <target-id> --profile osint --watch`,
	Args: cobra.ExactArgs(1),
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
		if err := client.Do(cmd.Context(), http.MethodPost, "/api/v1/recon/scans", body, &resp); err != nil {
			return err
		}
		if !scanStartWatch {
			return writeView(cmd, resp, scanTableHeaders, scanTableRows([]scanResponse{resp}))
		}
		// Watch: stream events from the scan. The endpoint is best-effort —
		// older servers without the SSE route still get a useful summary
		// printed above and then a clean exit.
		ctx := cmd.Context()
		path := "/api/v1/recon/scans/" + url.PathEscape(resp.ID) + "/events"
		err = client.Stream(ctx, path, func(event, data string) {
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
	Long: `Print recent scans across every target.

Default output is a table; use --output json|yaml for scripts.
The server's own filtering parameters are not exposed here yet —
use "recon findings list --target" to narrow further.`,
	Example: `  usulnet recon scan list
  usulnet recon scan list --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		client, err := reconClient()
		if err != nil {
			return err
		}
		var resp []scanResponse
		if err := client.Do(cmd.Context(), http.MethodGet, "/api/v1/recon/scans", nil, &resp); err != nil {
			return err
		}
		return writeView(cmd, resp, scanTableHeaders, scanTableRows(resp))
	},
}

var reconScanStatusCmd = &cobra.Command{
	Use:   "status <scan-id>",
	Short: "Show one scan's current status",
	Long: `Fetch the current status, engine, and timestamps for a
single scan by ID. Status is one of pending|running|completed|
failed|canceled.`,
	Example: `  usulnet recon scan status aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  usulnet recon scan status <scan-id> --output json`,
	Args: cobra.ExactArgs(1),
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
		if err := client.Do(cmd.Context(), http.MethodGet, path, nil, &resp); err != nil {
			return err
		}
		return writeView(cmd, resp, scanTableHeaders, scanTableRows([]scanResponse{resp}))
	},
}

var reconScanCancelCmd = &cobra.Command{
	Use:   "cancel <scan-id>",
	Short: "Cancel a running or queued scan",
	Long: `Request cancellation of a running or queued scan.

A finished scan (completed|failed|canceled) is left as-is; the
server responds 204 in both cases. Prints "canceled <id>" on
success.`,
	Example: `  usulnet recon scan cancel aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := reconClient()
		if err != nil {
			return err
		}
		path := "/api/v1/recon/scans/" + url.PathEscape(args[0])
		if err := client.Do(cmd.Context(), http.MethodDelete, path, nil, nil); err != nil {
			return err
		}
		infof(cmd, "canceled %s\n", args[0])
		return nil
	},
}

var reconScanReportCmd = &cobra.Command{
	Use:   "report <scan-id>",
	Short: "Download a scan report (--format json|csv|pdf, default json)",
	Long: `Download a completed scan's report.

The body is streamed to stdout — redirect to a file with
"> report.<ext>". Format is selected with --format (json|csv|pdf,
default json).`,
	Example: `  usulnet recon scan report <scan-id> > report.json
  usulnet recon scan report <scan-id> --format csv > report.csv
  usulnet recon scan report <scan-id> --format pdf > report.pdf`,
	Args: cobra.ExactArgs(1),
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
		req, err := client.NewRequest(cmd.Context(), http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		resp, err := client.HTTPClient().Do(req)
		if err != nil {
			return &apiclient.ErrNetwork{Op: "GET " + path, Err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 400 {
			buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return &apiclient.ErrStatus{
				Method: http.MethodGet,
				Path:   path,
				Status: resp.Status,
				Body:   bytes.TrimSpace(buf),
			}
		}
		_, err = io.Copy(cmd.OutOrStdout(), resp.Body)
		return err
	},
}

// -------------------------- recon findings -----------------------------------

var reconFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Browse findings produced by completed scans",
	Long: `Query the findings table that recon scans write to. Findings
are grouped by source module (e.g. sfp_shodan, sfp_hibp) and tagged
with a severity ladder (high / medium / low / info).

  list   page through findings with optional filters

Reads are scoped to the targets the calling user owns; admins see
every finding. The CLI uses the same auth surface as the web UI —
$USULNET_API_TOKEN or --token.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var reconFindingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings, optionally filtered by --target and --severity",
	Long: `List findings.

Without --target, the most recent scan's findings are listed.
With --target, every scan for that target is aggregated.
--severity (low|medium|high|critical) filters within the result.`,
	Example: `  usulnet recon findings list
  usulnet recon findings list --target <target-id>
  usulnet recon findings list --target <target-id> --severity high --output json`,
	Args: cobra.NoArgs,
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
			if err := client.Do(cmd.Context(), http.MethodGet, path, nil, &batch); err != nil {
				return err
			}
			out = append(out, batch...)
		}
		rows := make([][]string, 0, len(out))
		for _, f := range out {
			rows = append(rows, []string{f.Severity, f.Module, f.TargetID, truncate(f.Value, 60)})
		}
		return writeView(cmd, out,
			[]string{"SEVERITY", "MODULE", "TARGET", "VALUE"},
			rows,
		)
	},
}

// =============================================================================
// Helpers
// =============================================================================

// reconClient resolves an apiclient.Client from the recon-tree flags +
// env. It is re-resolved per command so unit tests can swap
// $USULNET_API_URL between invocations.
func reconClient() (*apiclient.Client, error) {
	return apiclient.New(apiclient.Options{
		BaseURL: reconAPIURL,
		Token:   reconAPIToken,
	})
}

// resolveProfileID looks up a profile by name (the form the CLI accepts) and
// returns its UUID. Callers may also pass a raw UUID, in which case it is
// returned verbatim.
func resolveProfileID(ctx context.Context, client *apiclient.Client, nameOrID string) (string, error) {
	if looksLikeUUID(nameOrID) {
		return nameOrID, nil
	}
	var profiles []profileResponse
	if err := client.Do(ctx, http.MethodGet, "/api/v1/recon/profiles", nil, &profiles); err != nil {
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
func listScansForFilter(ctx context.Context, client *apiclient.Client, targetID string) ([]scanResponse, error) {
	path := "/api/v1/recon/scans"
	if targetID != "" {
		path += "?target_id=" + url.QueryEscape(targetID)
	}
	var scans []scanResponse
	if err := client.Do(ctx, http.MethodGet, path, nil, &scans); err != nil {
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

// targetTableHeaders / targetTableRows split the table view of a target
// list from its column names. Used together with writeView so json/yaml
// output gets the structured response while table output gets the
// human-readable columns.
var targetTableHeaders = []string{"ID", "TYPE", "VALUE", "LABEL", "CREATED"}

func targetTableRows(items []targetResponse) [][]string {
	out := make([][]string, 0, len(items))
	for _, t := range items {
		out = append(out, []string{t.ID, t.Type, t.Value, t.Label, t.CreatedAt})
	}
	return out
}

var scanTableHeaders = []string{"ID", "TARGET", "PROFILE", "STATUS", "STARTED", "FINISHED"}

func scanTableRows(items []scanResponse) [][]string {
	out := make([][]string, 0, len(items))
	for _, s := range items {
		out = append(out, []string{s.ID, s.TargetID, s.ProfileID, s.Status, s.StartedAt, s.FinishedAt})
	}
	return out
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
// exit-code hint. The wrapper in main() consults this and writes the
// matching exit code on usage / infra / api failures.
//
// The apiclient package returns typed errors (ErrConfig, ErrNetwork,
// ErrAuth, ErrStatus); they're mapped here to the documented exit codes
// (70/71/72) so the apiclient package itself stays agnostic.
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
	// apiclient typed errors → exit codes
	var cfgErr *apiclient.ErrConfig
	if errors.As(err, &cfgErr) {
		return exitServerUnreach, true
	}
	var netErr *apiclient.ErrNetwork
	if errors.As(err, &netErr) {
		return exitServerUnreach, true
	}
	var authErr *apiclient.ErrAuth
	if errors.As(err, &authErr) {
		return exitAuth, true
	}
	var statusErr *apiclient.ErrStatus
	if errors.As(err, &statusErr) {
		return exitInfra, true
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
	// Global flags shared by recon + meta + every other subtree.
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "table", "output format: table|json|yaml")
	rootCmd.PersistentFlags().BoolVar(&outputJSONShortcut, "json", false, "shortcut for --output json (overrides --output)")
	rootCmd.PersistentFlags().BoolVarP(&quietMode, "quiet", "q", false, "suppress informational output (errors and primary data still print)")

	// Completion for the global --output enum. Registered on rootCmd so
	// every subcommand inherits it.
	mustRegisterFlagCompletion(rootCmd, "output",
		cobra.FixedCompletions(completeOutputFormats, cobra.ShellCompDirectiveNoFileComp))

	// PersistentPreRunE on rootCmd resolves --json → --output json
	// once for every subcommand. Subcommands keep their own RunE for
	// the actual work; the resolved outputFormat is read from the
	// package var.
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return resolveOutputFlags()
	}

	// recon flags
	reconCmd.PersistentFlags().StringVar(&reconAPIURL, "server", "", "usulnet API URL (default $USULNET_API_URL)")
	reconCmd.PersistentFlags().StringVar(&reconAPIToken, "token", "", "API token (default $USULNET_API_TOKEN)")

	// scan start flags
	reconScanStartCmd.Flags().StringVar(&scanStartProfile, "profile", "", "profile name or UUID (required)")
	reconScanStartCmd.Flags().BoolVar(&scanStartWatch, "watch", false, "stream scan events to stdout")
	mustRegisterFlagCompletion(reconScanStartCmd, "profile", completeReconProfileNames)

	// scan report flags
	reconScanReportCmd.Flags().StringVar(&scanReportFormat, "format", "json", "report format: json|csv|pdf")
	mustRegisterFlagCompletion(reconScanReportCmd, "format",
		cobra.FixedCompletions(completeReportFormats, cobra.ShellCompDirectiveNoFileComp))

	// findings flags
	reconFindingsListCmd.Flags().StringVar(&findingsTarget, "target", "", "filter findings by target ID")
	reconFindingsListCmd.Flags().StringVar(&findingsSeverity, "severity", "", "filter findings by severity")
	mustRegisterFlagCompletion(reconFindingsListCmd, "target", completeReconTargetIDs)
	mustRegisterFlagCompletion(reconFindingsListCmd, "severity",
		cobra.FixedCompletions(completeSeverityLevels, cobra.ShellCompDirectiveNoFileComp))

	// Positional completion for recon subcommands that take an ID. Each
	// ValidArgsFunction runs once per tab, talking to the local API
	// with a short timeout (see completion.go for the implementations).
	reconTargetAddCmd.ValidArgsFunction = completeReconTargetAddArgs
	reconTargetVerifyCmd.ValidArgsFunction = completeReconTargetIDs
	reconScanStartCmd.ValidArgsFunction = completeReconTargetIDs
	reconScanStatusCmd.ValidArgsFunction = completeReconScanIDs
	reconScanCancelCmd.ValidArgsFunction = completeReconScanIDs
	reconScanReportCmd.ValidArgsFunction = completeReconScanIDs

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
