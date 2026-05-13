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
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/metadata/extractor"
	"github.com/fr4nsys/usulnet/internal/services/metadata/stripper"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// metaCmd is the parent of all metadata-hygiene subcommands. Each
// subcommand can run in "server mode" (POST to the local API) or
// "local mode" (in-process Docker launcher + extractor + stripper).
//
// Mode selection: if --server is given or $USULNET_API_URL is set, server
// mode is used. Otherwise local mode runs directly against the host
// Docker daemon, which matches how a developer typically iterates on a
// laptop with no usulnet server running.
var metaCmd = &cobra.Command{
	Use:   "meta",
	Short: "Extract / strip file metadata via the recon-toolkit container",
	Long: `Manage file metadata using the recon-toolkit container (exiftool,
mat2, pdfid, oletools).

Two execution modes:
  server (--server URL or $USULNET_API_URL set) — POST to /api/v1/metadata/jobs.
  local  (default when no server is configured)  — run the toolkit container
                                                  directly against the host
                                                  Docker daemon.`,
}

// flags shared by every meta subcommand
var (
	metaServerURL  string
	metaServerTok  string
	metaToolkitImg string
	metaTimeout    string
)

// meta strip flags
var metaStripOutput string

// meta scan flags
var metaScanRecursive bool

// =============================================================================
// Cobra command definitions
// =============================================================================

var metaExtractCmd = &cobra.Command{
	Use:   "extract <path>",
	Short: "Print the metadata for one file as JSON / YAML / table",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		path := args[0]
		if useServerMode() {
			return runServerExtract(cmd, []string{path})
		}
		return runLocalExtract(cmd, path)
	},
}

var metaStripCmd = &cobra.Command{
	Use:   "strip <path>",
	Short: "Write a cleaned copy of the file (default: <path>.stripped)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if useServerMode() {
			return runServerStrip(cmd, path, metaStripOutput)
		}
		return runLocalStrip(cmd, path, metaStripOutput)
	},
}

var metaScanCmd = &cobra.Command{
	Use:   "scan <dir>",
	Short: "Extract metadata for every file under <dir> (recurse with --recursive)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(); err != nil {
			return err
		}
		paths, err := collectScanPaths(args[0], metaScanRecursive)
		if err != nil {
			return err
		}
		if useServerMode() {
			return runServerExtract(cmd, paths)
		}
		return runLocalScan(cmd, paths)
	},
}

// =============================================================================
// Server-mode implementations
// =============================================================================

// runServerExtract POSTs the files to /api/v1/metadata/jobs with mode=extract
// and prints the resulting job + artifacts.
func runServerExtract(cmd *cobra.Command, paths []string) error {
	client, err := metaClient()
	if err != nil {
		return err
	}
	job, err := postMetaJob(cmd.Context(), client, "extract", paths)
	if err != nil {
		return err
	}
	if outputFormat == "json" || outputFormat == "yaml" {
		return writeOutput(cmd, job)
	}
	rows := []tableRow{
		{"JOB", "STATUS", "ARTIFACTS"},
		{job.ID, job.Status, fmt.Sprintf("%d", job.ArtifactCount)},
	}
	return writeOutput(cmd, rows)
}

// runServerStrip POSTs the file with mode=strip, then downloads the cleaned
// bytes from the artifact stream into outputPath.
func runServerStrip(cmd *cobra.Command, path, outputPath string) error {
	client, err := metaClient()
	if err != nil {
		return err
	}
	job, err := postMetaJob(cmd.Context(), client, "strip", []string{path})
	if err != nil {
		return err
	}
	if len(job.Artifacts) == 0 {
		return &infraError{msg: "server returned no artifact", code: exitInfra}
	}
	if outputPath == "" {
		outputPath = path + ".stripped"
	}
	streamPath := fmt.Sprintf("/api/v1/metadata/jobs/%s/artifacts/%s/stripped",
		url.PathEscape(job.ID), url.PathEscape(job.Artifacts[0].ID))
	if err := downloadStream(cmd.Context(), client, streamPath, outputPath); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "stripped: %s -> %s\n", path, outputPath)
	return nil
}

// postMetaJob uploads `paths` as a multipart body to /api/v1/metadata/jobs.
func postMetaJob(ctx context.Context, client *apiClient, mode string, paths []string) (*metaJobResp, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("mode", mode); err != nil {
		return nil, err
	}
	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304 -- user-supplied CLI path
		if err != nil {
			return nil, &infraError{msg: fmt.Sprintf("open %s: %v", p, err), code: exitInfra}
		}
		fw, err := w.CreateFormFile("files", filepath.Base(p))
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err := io.Copy(fw, f); err != nil {
			_ = f.Close()
			return nil, err
		}
		_ = f.Close()
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/api/v1/metadata/jobs", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}
	resp, err := client.hc.Do(req)
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("api: %v", err), code: exitServerUnreach}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("api POST /metadata/jobs: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var out metaJobResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func downloadStream(ctx context.Context, client *apiClient, path, outputPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+path, nil)
	if err != nil {
		return err
	}
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}
	resp, err := client.hc.Do(req)
	if err != nil {
		return &infraError{msg: fmt.Sprintf("api: %v", err), code: exitServerUnreach}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("api GET %s: %s", path, resp.Status)
	}
	f, err := os.Create(outputPath) // #nosec G304 -- user-supplied CLI path
	if err != nil {
		return &infraError{msg: fmt.Sprintf("create %s: %v", outputPath, err), code: exitInfra}
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}

// metaJobResp is the small subset of metadata job fields the CLI displays.
type metaJobResp struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	ArtifactCount int    `json:"artifact_count"`
	Mode          string `json:"mode"`
	Artifacts     []struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
	} `json:"artifacts,omitempty"`
}

// =============================================================================
// Local-mode implementations
// =============================================================================

// localToolkit bundles the in-process dependencies needed for local
// extract/strip. Built on demand because each invocation also tears
// itself down — there is no persistent state.
type localToolkit struct {
	launcher recon.ContainerLauncher
	disp     metadata.Extractor
	strip    metadata.Stripper
	image    string
	closer   func() error
}

// newLocalToolkit constructs the Docker client + sandbox launcher and the
// metadata extractor + stripper that target the recon-toolkit image.
//
// The image is overridable via --image / $USULNET_RECON_TOOLKIT_IMAGE so
// developers can iterate against a locally-built `:dev` tag.
func newLocalToolkit(ctx context.Context) (*localToolkit, error) {
	image := metaToolkitImg
	if image == "" {
		image = os.Getenv("USULNET_RECON_TOOLKIT_IMAGE")
	}
	if image == "" {
		image = recon.ToolkitImage()
	}
	dockerCli, err := docker.NewClient(ctx, docker.ClientOptions{})
	if err != nil {
		return nil, &infraError{
			msg:  fmt.Sprintf("docker: %v", err),
			code: exitInfra,
		}
	}
	launcher, err := sandbox.NewLauncher(dockerCli, sandbox.Config{}, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("sandbox: %v", err), code: exitInfra}
	}
	exifT, err := extractor.NewExifTool(launcher, image, 0, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("extractor exiftool: %v", err), code: exitInfra}
	}
	pdfT, err := extractor.NewPDFID(launcher, image, 0, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("extractor pdfid: %v", err), code: exitInfra}
	}
	oleT, err := extractor.NewOleTools(launcher, image, 0, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("extractor oletools: %v", err), code: exitInfra}
	}
	disp, err := extractor.NewDispatch(exifT, pdfT, oleT, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("extractor dispatch: %v", err), code: exitInfra}
	}
	mat2, err := stripper.NewMat2(launcher, image, 0, logger.Nop())
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("stripper: %v", err), code: exitInfra}
	}
	return &localToolkit{
		launcher: launcher,
		disp:     disp,
		strip:    mat2,
		image:    image,
		closer:   func() error { return nil },
	}, nil
}

// runLocalExtract extracts metadata for one path and writes it.
func runLocalExtract(cmd *cobra.Command, path string) error {
	abs, err := absPath(path)
	if err != nil {
		return err
	}
	ctx, cancel, err := resolveTimeout(cmd.Context(), metaTimeout)
	if err != nil {
		return err
	}
	defer cancel()

	tk, err := newLocalToolkit(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tk.closer() }()

	out, err := tk.disp.Extract(ctx, metadata.ExtractInput{
		Path:     abs,
		Filename: filepath.Base(abs),
		MIME:     detectMIME(abs),
	})
	if err != nil {
		return &infraError{msg: fmt.Sprintf("extract: %v", err), code: exitInfra}
	}
	doc := map[string]any{
		"path":     abs,
		"filename": filepath.Base(abs),
		"mime":     detectMIME(abs),
		"metadata": out,
	}
	if outputFormat == "json" || outputFormat == "yaml" {
		return writeOutput(cmd, doc)
	}
	rows := []tableRow{
		{"FIELD", "VALUE"},
		{"path", abs},
		{"mime", detectMIME(abs)},
	}
	for k, v := range flattenMetadata(out) {
		rows = append(rows, tableRow{k, fmt.Sprintf("%v", v)})
	}
	return writeOutput(cmd, rows)
}

// runLocalStrip runs mat2 against the supplied path and copies the cleaned
// bytes to outputPath (defaulting to <path>.stripped).
func runLocalStrip(cmd *cobra.Command, path, outputPath string) error {
	abs, err := absPath(path)
	if err != nil {
		return err
	}
	if outputPath == "" {
		outputPath = path + ".stripped"
	}
	absOut, err := filepath.Abs(outputPath)
	if err != nil {
		return &infraError{msg: fmt.Sprintf("resolve output: %v", err), code: exitInfra}
	}
	ctx, cancel, err := resolveTimeout(cmd.Context(), metaTimeout)
	if err != nil {
		return err
	}
	defer cancel()

	tk, err := newLocalToolkit(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tk.closer() }()

	res, err := tk.strip.Strip(ctx, metadata.StripInput{
		Path:     abs,
		Filename: filepath.Base(abs),
		MIME:     detectMIME(abs),
	})
	if err != nil {
		return &infraError{msg: fmt.Sprintf("strip: %v", err), code: exitInfra}
	}
	// The stripper writes the cleaned copy next to the input (as `stripped`).
	// Rename it to the user-requested location.
	if res.CleanedPath != absOut {
		if err := os.Rename(res.CleanedPath, absOut); err != nil {
			return &infraError{msg: fmt.Sprintf("rename: %v", err), code: exitInfra}
		}
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "stripped: %s -> %s (%d bytes)\n", abs, absOut, res.SizeBytes)
	return nil
}

// runLocalScan walks the file list, extracting metadata for each and
// collecting per-file errors. Per docs/recon.md §8, a failure on any
// individual file leaves the rest of the report intact and the command
// exits 2.
func runLocalScan(cmd *cobra.Command, paths []string) error {
	ctx, cancel, err := resolveTimeout(cmd.Context(), metaTimeout)
	if err != nil {
		return err
	}
	defer cancel()

	tk, err := newLocalToolkit(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tk.closer() }()

	type fileReport struct {
		Path     string         `json:"path"`
		MIME     string         `json:"mime"`
		Metadata map[string]any `json:"metadata,omitempty"`
		Error    string         `json:"error,omitempty"`
	}

	results := make([]fileReport, 0, len(paths))
	failures := 0
	for _, p := range paths {
		abs, err := absPath(p)
		if err != nil {
			results = append(results, fileReport{Path: p, Error: err.Error()})
			failures++
			continue
		}
		out, err := tk.disp.Extract(ctx, metadata.ExtractInput{
			Path:     abs,
			Filename: filepath.Base(abs),
			MIME:     detectMIME(abs),
		})
		if err != nil {
			results = append(results, fileReport{Path: abs, MIME: detectMIME(abs), Error: err.Error()})
			failures++
			continue
		}
		results = append(results, fileReport{Path: abs, MIME: detectMIME(abs), Metadata: out})
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		if err := writeOutput(cmd, results); err != nil {
			return err
		}
	} else {
		rows := []tableRow{{"PATH", "MIME", "STATUS"}}
		for _, r := range results {
			status := "ok"
			if r.Error != "" {
				status = "error: " + r.Error
			}
			rows = append(rows, tableRow{r.Path, r.MIME, status})
		}
		if err := writeOutput(cmd, rows); err != nil {
			return err
		}
	}

	if failures > 0 {
		// Surface a per-file failure via the documented exit code, but keep
		// the report on stdout for downstream tools to consume.
		return &perFileError{count: failures}
	}
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

// perFileError signals one or more per-file failures during a scan. The
// rootCmd error translator maps it to exit code 2 per docs/recon.md §8.
type perFileError struct{ count int }

func (e *perFileError) Error() string {
	return fmt.Sprintf("%d file(s) failed during scan", e.count)
}

func useServerMode() bool {
	if metaServerURL != "" {
		return true
	}
	if os.Getenv("USULNET_API_URL") != "" {
		return true
	}
	return false
}

// metaClient resolves the apiClient used by server-mode meta commands.
// It honors --server / --token then falls back to environment.
func metaClient() (*apiClient, error) {
	return newAPIClient(apiClientOptions{
		BaseURL: metaServerURL,
		Token:   metaServerTok,
	})
}

// collectScanPaths returns every file under `dir`. If recursive is false,
// only immediate children are returned. Sub-directories never appear in
// the result; they are walked or skipped silently.
func collectScanPaths(dir string, recursive bool) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("scan: %v", err)}
	}
	if !info.IsDir() {
		return []string{dir}, nil
	}
	var out []string
	if recursive {
		err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, &infraError{msg: fmt.Sprintf("walk: %v", err), code: exitInfra}
		}
		return out, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &infraError{msg: fmt.Sprintf("readdir: %v", err), code: exitInfra}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}

func absPath(p string) (string, error) {
	if _, err := os.Stat(p); err != nil {
		return "", &usageError{msg: fmt.Sprintf("path: %v", err)}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", &infraError{msg: fmt.Sprintf("abs path: %v", err), code: exitInfra}
	}
	return abs, nil
}

// detectMIME returns a MIME guess based on the file extension. The toolkit
// extractors fall back to exiftool's own detection when the MIME is empty
// or unknown, so a best-effort guess here is sufficient.
func detectMIME(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return "application/octet-stream"
	}
	// Special-case formats whose mime.TypeByExtension answers vary
	// across platforms (HEIC ↔ HEIF, WEBP missing on older libc).
	switch ext {
	case ".heic":
		return "image/heic"
	case ".webp":
		return "image/webp"
	}
	if m := mime.TypeByExtension(ext); m != "" {
		// mime.TypeByExtension may return "image/jpeg; charset=utf-8";
		// strip parameters so the toolkit's MIME switch matches.
		if i := strings.Index(m, ";"); i >= 0 {
			return strings.TrimSpace(m[:i])
		}
		return m
	}
	return "application/octet-stream"
}

// flattenMetadata returns the "exiftool" sub-map (the universal extractor
// output) for table rendering. Other tools' output is keyed under their
// name and is dropped here because it would not render well in a flat
// table; the JSON/YAML modes still include it.
func flattenMetadata(out map[string]any) map[string]any {
	exif, ok := out["exiftool"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return exif
}

// hasMetaError is kept as an alias to satisfy the same error→exit-code
// contract used by the recon tree. perFileError is the only type local to
// meta.go; everything else (usageError, infraError) is shared with recon.
func init() {
	// Persistent meta flags.
	metaCmd.PersistentFlags().StringVar(&metaServerURL, "server", "", "usulnet API URL (forces server mode; default $USULNET_API_URL)")
	metaCmd.PersistentFlags().StringVar(&metaServerTok, "token", "", "API token (default $USULNET_API_TOKEN)")
	metaCmd.PersistentFlags().StringVar(&metaToolkitImg, "image", "", "toolkit image (local mode only; default $USULNET_RECON_TOOLKIT_IMAGE)")
	metaCmd.PersistentFlags().StringVar(&metaTimeout, "timeout", "", "container timeout (e.g. 30s)")

	// strip flags
	metaStripCmd.Flags().StringVarP(&metaStripOutput, "output", "o", "", "output path for cleaned file (default <input>.stripped)")

	// scan flags
	metaScanCmd.Flags().BoolVarP(&metaScanRecursive, "recursive", "r", false, "recurse into subdirectories")

	metaCmd.AddCommand(metaExtractCmd)
	metaCmd.AddCommand(metaStripCmd)
	metaCmd.AddCommand(metaScanCmd)

	rootCmd.AddCommand(metaCmd)
}

// extendReconErrorMapping ensures perFileError reports exit code 2 through
// the same shared translator (hasReconError in recon.go). The translator
// looks for typed errors via errors.As; we expose a small wrapper that
// keeps the canonical mapping in one place.
//
// (Implemented as a global function so tests can call it directly without
// running the full cobra wrapper.)
func metaExitCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var pf *perFileError
	if errors.As(err, &pf) {
		return exitPerFileFailures, true
	}
	return hasReconError(err)
}

// Suppress unused-symbol warnings in builds that skip the local mode.
var _ = time.Second
var _ = reconLocalArtifactsDir
