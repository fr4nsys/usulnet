// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package smoke is the release-gate smoke test for usulnet (Tier 0 /
// session 01 of the v26.5.2 plan). It exists because the v26.5.1
// image shipped to Docker Hub with a chi-router panic that crash-
// looped the binary on first boot — a class of bug that no unit test
// catches but a single curl against the dashboard would have.
//
// Contract:
//
//   1. Brings up the canonical docker-compose stack with the e2e
//      overlay against a freshly built `usulnet/usulnet:test` image.
//   2. Polls /health until 200 (max 120 s).
//   3. Logs in as admin / usulnet (the bootstrap default).
//   4. Parses the dashboard HTML and extracts every href="/..." in
//      the <nav>.
//   5. GETs each route, asserts status ∈ {200, 301, 302, 303}.
//   6. Scrapes `docker logs usulnet` at the end and fails on
//      "panic:" or `"level":"fatal"`.
//
// Run with:
//
//   make smoke-e2e
//
// or:
//
//   go test -tags=e2e -v -timeout 5m ./tests/e2e/smoke/...
//
// The test assumes:
//   - The binary `docker` is on PATH.
//   - The repository checkout matches the docker-compose.yml + .env.example
//     in the working dir.
//   - The smoke runner has permission to bind ports 7443 + the
//     internal backend ports (postgres/redis/nats are on the
//     docker-internal network).
package smoke

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	// baseURL is the usulnet HTTPS endpoint from the canonical compose.
	baseURL = "https://localhost:7443"

	// adminUser / adminPass are the bootstrap admin credentials. The
	// server logs a warning on first start telling the operator to
	// change them; the smoke test logs in as them before any change.
	adminUser = "admin"
	adminPass = "usulnet"

	// healthTimeout caps the wait between `compose up -d` and the first
	// healthy response from /health.
	healthTimeout = 120 * time.Second

	// healthPoll is the polling interval inside healthTimeout.
	healthPoll = 2 * time.Second

	// composeProject pins the compose project name so the cleanup
	// always targets the same stack regardless of the calling dir.
	composeProject = "usulnet-smoke-e2e"
)

// hrefRE extracts each href="/..." from the rendered dashboard HTML.
// It deliberately ignores external links (https?://) and anchors.
var hrefRE = regexp.MustCompile(`href="(/[^"#?]*)"`)

// csrfRE captures the value of the hidden csrf_token input rendered on
// every state-changing form. Used by completeOnboarding to forward
// the token through the wizard POSTs.
var csrfRE = regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)

// TestSmokeE2E is the single end-to-end smoke. Failure of any sub-step
// aborts the test so the operator gets the earliest signal.
func TestSmokeE2E(t *testing.T) {
	if os.Getenv("USULNET_SKIP_SMOKE") == "1" {
		t.Skip("USULNET_SKIP_SMOKE=1 set; skipping smoke")
	}

	// All compose commands need to run from the repo root where
	// docker-compose.yml and the overlay live. The test binary is
	// invoked from `tests/e2e/smoke/` by `go test`.
	if err := chdirRepoRoot(); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}

	t.Logf("smoke: bringing up stack with overlay docker-compose.e2e.yml")
	if err := composeUp(t); err != nil {
		t.Fatalf("compose up: %v", err)
	}
	t.Cleanup(func() {
		_ = composeDown(t)
	})

	t.Logf("smoke: polling /health (timeout %s)", healthTimeout)
	if err := waitForHealth(t); err != nil {
		t.Fatalf("waiting for /health: %v", err)
	}

	t.Logf("smoke: logging in as %s", adminUser)
	client, err := login()
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// The v26.5.2 onboarding wizard redirects every authenticated
	// admin route at /onboarding/welcome until the bootstrap password
	// is changed and the flag is flipped. Smoke walks chrome routes;
	// it has to clear the wizard first or every walkRoute lands on
	// the welcome page.
	t.Logf("smoke: completing onboarding wizard")
	if err := completeOnboarding(client); err != nil {
		t.Fatalf("completing onboarding wizard: %v", err)
	}

	t.Logf("smoke: discovering routes from dashboard")
	routes, err := discoverRoutes(client)
	if err != nil {
		t.Fatalf("discovering routes: %v", err)
	}
	if len(routes) < 20 {
		t.Fatalf("smoke: only %d routes discovered; expected ≥20 — sidebar may have failed to render", len(routes))
	}
	t.Logf("smoke: %d unique routes to walk", len(routes))

	var failures []string
	for _, r := range routes {
		if shouldSkipRoute(r) {
			continue
		}
		status, err := walkRoute(client, r)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("%s: %v", r, err))
		case !okStatus(status):
			failures = append(failures, fmt.Sprintf("%s: HTTP %d", r, status))
		}
	}

	if len(failures) > 0 {
		t.Errorf("smoke: %d routes failed:", len(failures))
		for _, f := range failures {
			t.Errorf("  - %s", f)
		}
	}

	t.Logf("smoke: scraping container logs for panics")
	if err := assertCleanLogs(t); err != nil {
		t.Errorf("smoke: container logs contain fatal markers: %v", err)
	}
}

// composeUp builds the local image and brings up the stack with the
// e2e overlay. It writes a minimal .env on the fly so secrets are
// random per run.
func composeUp(t *testing.T) error {
	envFile := writeEnv(t)
	t.Cleanup(func() {
		_ = os.Remove(envFile)
	})

	// Build the image from this checkout so the smoke gates against
	// THIS commit, not whatever Docker Hub has. The image build is
	// skippable via USULNET_SMOKE_SKIP_BUILD=1 for fast local
	// iteration when an existing `usulnet/usulnet:test` tag is
	// already present (e.g. while debugging the test itself).
	if os.Getenv("USULNET_SMOKE_SKIP_BUILD") != "1" {
		build := exec.Command("docker", "build", "-t", "usulnet/usulnet:test", ".")
		build.Stdout, build.Stderr = nil, nil
		if testing.Verbose() {
			build.Stdout, build.Stderr = os.Stdout, os.Stderr
		}
		if err := build.Run(); err != nil {
			return fmt.Errorf("docker build: %w", err)
		}
	}

	up := exec.Command(
		"docker", "compose",
		"-p", composeProject,
		"--env-file", envFile,
		"-f", "docker-compose.yml",
		"-f", "docker-compose.e2e.yml",
		"up", "-d", "--wait", "--wait-timeout", "120",
	)
	if testing.Verbose() {
		up.Stdout, up.Stderr = os.Stdout, os.Stderr
	}
	return up.Run()
}

// composeDown tears the stack down and removes volumes / networks.
func composeDown(t *testing.T) error {
	down := exec.Command(
		"docker", "compose",
		"-p", composeProject,
		"-f", "docker-compose.yml",
		"-f", "docker-compose.e2e.yml",
		"down", "-v", "--remove-orphans",
	)
	if testing.Verbose() {
		down.Stdout, down.Stderr = os.Stdout, os.Stderr
	}
	return down.Run()
}

// writeEnv writes a per-run .env with random secrets so smoke runs
// don't share crypto state with each other.
func writeEnv(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "usulnet-smoke-*.env")
	if err != nil {
		t.Fatalf("create env file: %v", err)
	}
	defer f.Close()

	const tpl = `DB_PASSWORD=%s
JWT_SECRET=%s
ENCRYPTION_KEY=%s
USULNET_VERSION=test
USULNET_MODE=standalone
USULNET_HTTPS_PORT=7443
DB_USER=usulnet
DB_NAME=usulnet
HOST_TERMINAL_ENABLED=false
GUACD_ENABLED=false
`
	dbPass := randomHex(16)
	jwt := randomHex(32)
	enc := randomHex(32)
	if _, err := fmt.Fprintf(f, tpl, dbPass, jwt, enc); err != nil {
		t.Fatalf("write env: %v", err)
	}
	return f.Name()
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(randSource(), b); err != nil {
		panic(err)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// waitForHealth polls GET /health (over HTTPS, ignoring the
// self-signed cert) until 200 or timeout.
func waitForHealth(t *testing.T) error {
	deadline := time.Now().Add(healthTimeout)
	client := insecureClient()
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(healthPoll)
	}
	// On failure, dump the last lines of the container log to help
	// debugging in CI.
	dumpLogs(t)
	return fmt.Errorf("/health never returned 200 within %s", healthTimeout)
}

// login performs the form-POST against /login and returns an
// authenticated HTTP client.
func login() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := insecureClient()
	client.Jar = jar
	// Stop after the post; we want to inspect the redirect ourselves.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{}
	form.Set("username", adminUser)
	form.Set("password", adminPass)

	req, err := http.NewRequest(http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("login POST: expected 303 / 302, got %d", resp.StatusCode)
	}
	// Re-enable redirect following for the subsequent walks.
	client.CheckRedirect = nil
	return client, nil
}

// discoverRoutes fetches `/` and extracts every internal href="/..."
// inside the rendered HTML. Returns a deduplicated, sorted slice.
func discoverRoutes(client *http.Client) ([]string, error) {
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET / for route discovery: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, m := range hrefRE.FindAllStringSubmatch(string(body), -1) {
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Stable order for the test log.
	sortStrings(out)
	return out, nil
}

// shouldSkipRoute filters routes that are not part of the smoke
// contract (static assets, file-download endpoints, per-resource
// detail pages discovered from the dashboard but not gated for
// smoke).
func shouldSkipRoute(r string) bool {
	switch {
	case strings.HasPrefix(r, "/static/"):
		return true
	case strings.HasPrefix(r, "/api/"):
		return true
	// container detail / logs pages discovered from the dashboard's
	// "recent containers" list — these reference live container IDs
	// from the running daemon and are not part of the chrome-level
	// smoke we care about.
	case strings.HasPrefix(r, "/containers/") && r != "/containers" && r != "/containers/new":
		return true
	}
	return false
}

// walkRoute fetches a single route and returns the status code.
func walkRoute(client *http.Client, route string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+route, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func okStatus(s int) bool {
	return s == http.StatusOK ||
		s == http.StatusMovedPermanently ||
		s == http.StatusFound ||
		s == http.StatusSeeOther
}

// assertCleanLogs greps the usulnet container log for panic / fatal
// markers. Any hit fails the test.
func assertCleanLogs(t *testing.T) error {
	t.Helper()
	logs, err := exec.Command(
		"docker", "compose",
		"-p", composeProject,
		"-f", "docker-compose.yml",
		"-f", "docker-compose.e2e.yml",
		"logs", "--no-color", "usulnet",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose logs: %w", err)
	}
	text := string(logs)
	bad := []string{
		"panic:",
		`"level":"fatal"`,
		"runtime error:",
	}
	for _, marker := range bad {
		if strings.Contains(text, marker) {
			// Surface the last 40 lines for debugging.
			lines := strings.Split(text, "\n")
			tail := lines
			if len(lines) > 40 {
				tail = lines[len(lines)-40:]
			}
			t.Logf("smoke: container log tail:\n%s", strings.Join(tail, "\n"))
			return fmt.Errorf("container log contains %q", marker)
		}
	}
	return nil
}

// dumpLogs is called on health-poll failure to give CI a chance to
// debug a stuck startup.
func dumpLogs(t *testing.T) {
	t.Helper()
	logs, err := exec.Command(
		"docker", "compose",
		"-p", composeProject,
		"-f", "docker-compose.yml",
		"-f", "docker-compose.e2e.yml",
		"logs", "--no-color", "--tail", "100", "usulnet",
	).CombinedOutput()
	if err != nil {
		t.Logf("smoke: docker compose logs failed: %v", err)
		return
	}
	t.Logf("smoke: container log tail on health-wait failure:\n%s", logs)
}

// insecureClient returns an HTTPS client that trusts the
// self-signed cert the bootstrap generates at first start. The smoke
// runs against a freshly built container; the cert is ephemeral.
func insecureClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Smoke test only — the container generates its
				// own self-signed cert and the test is run against
				// localhost in CI. NOT for production.
				InsecureSkipVerify: true, //nolint:gosec // smoke E2E
			},
		},
	}
}

// sortStrings is a tiny local helper to keep the import list small.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// chdirRepoRoot walks up from the test's working dir until it finds
// docker-compose.yml (the repo-root marker we need) and chdirs there.
// `go test ./tests/e2e/smoke/...` runs from the package dir; everything
// else (CI runners, `make smoke-e2e` from the repo root) already starts
// in the right place. Either way, this normalises the cwd.
func chdirRepoRoot() error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(dir + "/docker-compose.yml"); err == nil {
			return os.Chdir(dir)
		}
		parent := dir + "/.."
		abs, err := absPath(parent)
		if err != nil {
			return err
		}
		if abs == dir {
			break
		}
		dir = abs
	}
	return fmt.Errorf("docker-compose.yml not found walking up from %s", cwd)
}

func absPath(p string) (string, error) {
	resolved, err := exec.Command("readlink", "-f", p).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(resolved)), nil
}

// smokeWizardPassword is the password the test sets on the bootstrap
// admin during the v26.5.2 onboarding wizard. It must satisfy
// validateWizardPassword in handler_onboarding.go (>= 12 runes, not
// equal to the username, not the literal "usulnet"). The test never
// uses this password after the wizard finishes; the rest of the
// smoke run uses the same session cookie from login().
const smokeWizardPassword = "SmokeTestPwd!2026"

// completeOnboarding walks the v26.5.2 wizard so the rest of the
// smoke run sees the dashboard instead of the welcome redirect.
//
// Sequence:
//
//	GET /onboarding/welcome → harvest csrf_token from the rendered form
//	POST /onboarding/welcome (new_password + confirm + csrf)
//	GET  /onboarding/done    → harvest fresh csrf_token
//	POST /onboarding/finish  (csrf)
//
// After the final POST the onboarding_completed flag is set, the
// middleware stops redirecting, and the operator (in this case, the
// test) can walk the rest of the routes normally.
func completeOnboarding(client *http.Client) error {
	csrf, err := fetchCSRFToken(client, baseURL+"/onboarding/welcome")
	if err != nil {
		return fmt.Errorf("welcome GET: %w", err)
	}

	form := url.Values{}
	form.Set("csrf_token", csrf)
	form.Set("new_password", smokeWizardPassword)
	form.Set("confirm_password", smokeWizardPassword)
	if err := postForm(client, baseURL+"/onboarding/welcome", form); err != nil {
		return fmt.Errorf("welcome POST: %w", err)
	}

	csrf, err = fetchCSRFToken(client, baseURL+"/onboarding/done")
	if err != nil {
		return fmt.Errorf("done GET: %w", err)
	}

	form = url.Values{}
	form.Set("csrf_token", csrf)
	if err := postForm(client, baseURL+"/onboarding/finish", form); err != nil {
		return fmt.Errorf("finish POST: %w", err)
	}
	return nil
}

// fetchCSRFToken does a GET and parses the csrf_token hidden input out
// of the response body. Returns an error if the request fails or the
// token isn't present.
func fetchCSRFToken(client *http.Client, urlStr string) (string, error) {
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", urlStr, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := csrfRE.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("csrf_token not found in response from %s", urlStr)
	}
	return string(m[1]), nil
}

// postForm POSTs a url-encoded form and accepts any 2xx or 3xx as
// success. The wizard handlers redirect on success (303 → next step
// or /), so we don't follow but we also don't fail on the redirect.
func postForm(client *http.Client, urlStr string, form url.Values) error {
	req, err := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s: HTTP %d", urlStr, resp.StatusCode)
	}
	return nil
}
