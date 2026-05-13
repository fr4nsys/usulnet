// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/scheduler"
)

// ============================================================================
// nilServices: implements Services interface with all methods returning nil.
// This simulates the state when no backend services are configured.
// ============================================================================

type nilServices struct{}

func (n *nilServices) Containers() ContainerService   { return nil }
func (n *nilServices) Images() ImageService           { return nil }
func (n *nilServices) Volumes() VolumeService         { return nil }
func (n *nilServices) Networks() NetworkService       { return nil }
func (n *nilServices) Stacks() StackService           { return nil }
func (n *nilServices) Backups() BackupService         { return nil }
func (n *nilServices) Config() ConfigService          { return nil }
func (n *nilServices) Security() SecurityService      { return nil }
func (n *nilServices) Updates() UpdateService         { return nil }
func (n *nilServices) Hosts() HostService             { return nil }
func (n *nilServices) Events() EventService           { return nil }
func (n *nilServices) Proxy() ProxyService            { return nil }
func (n *nilServices) Storage() StorageService        { return nil }
func (n *nilServices) Auth() AuthService              { return nil }
func (n *nilServices) Stats() StatsService            { return nil }
func (n *nilServices) Users() UserService             { return nil }
func (n *nilServices) Teams() TeamService             { return nil }
func (n *nilServices) Gitea() GiteaService            { return nil }
func (n *nilServices) Git() GitService                { return nil }
func (n *nilServices) Metrics() MetricsServiceFull    { return nil }
func (n *nilServices) Alerts() AlertsService          { return nil }
func (n *nilServices) Scheduler() *scheduler.Scheduler { return nil }

// ============================================================================
// testLogger: implements Logger interface (discards all output)
// ============================================================================

type testLogger struct{}

func (l *testLogger) Error(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Warn(msg string, args ...interface{})  {}

// ============================================================================
// Test helpers
// ============================================================================

// newTestHandler creates a Handler with nil-safe service registry.
// All services return nil, simulating unconfigured backends.
func newTestHandler() *Handler {
	h := &Handler{}
	h.services = &nilServices{}
	h.logger = &testLogger{}
	return h
}

// requestWithChi creates a request with chi URL params.
func requestWithChi(method, path string, params map[string]string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	if params != nil {
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// requestWithForm creates a POST request with form data and chi params.
func requestWithForm(path string, formData string, params map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	if params != nil {
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// assertNoPanic asserts that calling fn does not panic.
func assertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	fn()
}

// assertStatusCode checks the response status code.
func assertStatusCode(t *testing.T, name string, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: status = %d, want %d", name, rec.Code, want)
	}
}

// ============================================================================
// Proxy ext handlers: nil safety tests (30+ potential panics)
// ============================================================================

func TestProxyExtHandlers_NilService(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		params  map[string]string
	}{
		// Certificate handlers
		{"CertListTempl", h.CertListTempl, "GET", nil},
		{"CertNewLETempl", h.CertNewLETempl, "GET", nil},
		{"CertNewCustomTempl", h.CertNewCustomTempl, "GET", nil},
		{"CertDetailTempl", h.CertDetailTempl, "GET", map[string]string{"id": "1"}},
		{"CertRenew", h.CertRenew, "POST", map[string]string{"id": "1"}},
		{"CertDelete", h.CertDelete, "DELETE", map[string]string{"id": "1"}},
		// Redirection handlers
		{"RedirListTempl", h.RedirListTempl, "GET", nil},
		{"RedirNewTempl", h.RedirNewTempl, "GET", nil},
		{"RedirEditTempl", h.RedirEditTempl, "GET", map[string]string{"id": "1"}},
		{"RedirDelete", h.RedirDelete, "DELETE", map[string]string{"id": "1"}},
		// Stream handlers
		{"StreamListTempl", h.StreamListTempl, "GET", nil},
		{"StreamNewTempl", h.StreamNewTempl, "GET", nil},
		{"StreamEditTempl", h.StreamEditTempl, "GET", map[string]string{"id": "1"}},
		{"StreamDelete", h.StreamDelete, "DELETE", map[string]string{"id": "1"}},
		// Dead host handlers
		{"DeadListTempl", h.DeadListTempl, "GET", nil},
		{"DeadNewTempl", h.DeadNewTempl, "GET", nil},
		{"DeadDelete", h.DeadDelete, "DELETE", map[string]string{"id": "1"}},
		// ACL handlers
		{"ACLListTempl", h.ACLListTempl, "GET", nil},
		{"ACLNewTempl", h.ACLNewTempl, "GET", nil},
		{"ACLEditTempl", h.ACLEditTempl, "GET", map[string]string{"id": "1"}},
		{"ACLDelete", h.ACLDelete, "DELETE", map[string]string{"id": "1"}},
		// Audit handler
		{"AuditListTempl", h.AuditListTempl, "GET", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_no_panic", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := requestWithChi(tt.method, "/proxy/test", tt.params)
			assertNoPanic(t, tt.name, func() {
				tt.handler(rec, req)
			})
		})
	}
}

// ============================================================================
// Auto-update handlers: nil safety tests
// ============================================================================

func TestAutoUpdateHandlers_NilService(t *testing.T) {
	h := newTestHandler()

	t.Run("AutoUpdatePoliciesTempl_no_panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("GET", "/updates/policies", nil)
		assertNoPanic(t, "AutoUpdatePoliciesTempl", func() {
			h.AutoUpdatePoliciesTempl(rec, req)
		})
	})

	t.Run("AutoUpdatePolicyCreate_redirects_on_nil", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithForm("/updates/policies", "container_id=test&container_name=test", nil)
		assertNoPanic(t, "AutoUpdatePolicyCreate", func() {
			h.AutoUpdatePolicyCreate(rec, req)
		})
		assertStatusCode(t, "AutoUpdatePolicyCreate", rec, http.StatusSeeOther)
	})

	t.Run("AutoUpdatePolicyToggle_no_panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("POST", "/updates/policies/1/toggle", map[string]string{"id": "1"})
		assertNoPanic(t, "AutoUpdatePolicyToggle", func() {
			h.AutoUpdatePolicyToggle(rec, req)
		})
	})

	t.Run("AutoUpdatePolicyDelete_no_panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("DELETE", "/updates/policies/1", map[string]string{"id": "1"})
		assertNoPanic(t, "AutoUpdatePolicyDelete", func() {
			h.AutoUpdatePolicyDelete(rec, req)
		})
	})
}

// ============================================================================
// Quotas handlers: nil safety tests
// ============================================================================

func TestQuotaHandlers_NilService(t *testing.T) {
	h := newTestHandler()

	t.Run("QuotaCreate_redirects", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithForm("/quotas", "name=test&limit_value=100&resource_type=containers&scope=global", nil)
		assertNoPanic(t, "QuotaCreate", func() {
			h.QuotaCreate(rec, req)
		})
		assertStatusCode(t, "QuotaCreate", rec, http.StatusSeeOther)
	})

	t.Run("QuotaToggle_no_panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("POST", "/quotas/1/toggle", map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"})
		assertNoPanic(t, "QuotaToggle", func() {
			h.QuotaToggle(rec, req)
		})
	})

	t.Run("QuotaDelete_no_panic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("DELETE", "/quotas/1", map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"})
		assertNoPanic(t, "QuotaDelete", func() {
			h.QuotaDelete(rec, req)
		})
	})
}

// ============================================================================
// Access Audit handlers tests
// ============================================================================

func TestAccessAuditHandlers(t *testing.T) {
	h := newTestHandler()

	t.Run("AccessAuditExport_content_type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := requestWithChi("GET", "/access-audit/export", nil)
		assertNoPanic(t, "AccessAuditExport", func() {
			h.AccessAuditExport(rec, req)
		})
		if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
			t.Errorf("Content-Type = %q, want %q", ct, "text/csv")
		}
		if disp := rec.Header().Get("Content-Disposition"); !strings.Contains(disp, "access_audit.csv") {
			t.Errorf("Content-Disposition = %q, want to contain %q", disp, "access_audit.csv")
		}
	})
}

// ============================================================================
// RecordAccessEvent tests
// ============================================================================

func TestRecordAccessEvent(t *testing.T) {
	// Reset global state
	accessAuditMu.Lock()
	origEntries := accessAuditEntries
	accessAuditEntries = nil
	accessAuditMu.Unlock()
	defer func() {
		accessAuditMu.Lock()
		accessAuditEntries = origEntries
		accessAuditMu.Unlock()
	}()

	t.Run("records_event", func(t *testing.T) {
		RecordAccessEvent("admin", "uid-1", "login", "session", "s1", "admin-session", "Login from web", "127.0.0.1", "TestBrowser", true, "")

		accessAuditMu.RLock()
		defer accessAuditMu.RUnlock()
		if len(accessAuditEntries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(accessAuditEntries))
		}
		if accessAuditEntries[0].UserName != "admin" {
			t.Errorf("UserName = %q, want %q", accessAuditEntries[0].UserName, "admin")
		}
		if !accessAuditEntries[0].Success {
			t.Error("Success should be true")
		}
	})

	t.Run("prepends_new_entries", func(t *testing.T) {
		RecordAccessEvent("user2", "uid-2", "delete", "container", "c1", "nginx", "Deleted", "10.0.0.1", "TestBrowser", true, "")

		accessAuditMu.RLock()
		defer accessAuditMu.RUnlock()
		if len(accessAuditEntries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(accessAuditEntries))
		}
		if accessAuditEntries[0].UserName != "user2" {
			t.Errorf("newest entry should be first, got %q", accessAuditEntries[0].UserName)
		}
	})

	t.Run("caps_at_500", func(t *testing.T) {
		accessAuditMu.Lock()
		accessAuditEntries = nil
		accessAuditMu.Unlock()

		for i := 0; i < 510; i++ {
			RecordAccessEvent("user", "uid", "action", "res", "id", "name", "", "ip", "ua", true, "")
		}

		accessAuditMu.RLock()
		defer accessAuditMu.RUnlock()
		if len(accessAuditEntries) != 500 {
			t.Errorf("expected 500 max, got %d", len(accessAuditEntries))
		}
	})
}

// ============================================================================
// Audit helper tests
// ============================================================================

func TestAuditActionIcon(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"login", "fas fa-sign-in-alt"},
		{"logout", "fas fa-sign-out-alt"},
		{"login_failed", "fas fa-user-times"},
		{"create", "fas fa-plus"},
		{"update", "fas fa-edit"},
		{"delete", "fas fa-trash"},
		{"start", "fas fa-play"},
		{"stop", "fas fa-stop"},
		{"restart", "fas fa-redo"},
		{"backup", "fas fa-archive"},
		{"restore", "fas fa-undo"},
		{"security_scan", "fas fa-shield-alt"},
		{"password_change", "fas fa-key"},
		{"api_key_create", "fas fa-key"},
		{"unknown_action", "fas fa-circle"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := auditActionIcon(tt.action)
			if got != tt.want {
				t.Errorf("auditActionIcon(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestAuditActionColor(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"login", "text-green-400"},
		{"logout", "text-gray-400"},
		{"login_failed", "text-red-400"},
		{"create", "text-blue-400"},
		{"update", "text-yellow-400"},
		{"delete", "text-red-400"},
		{"start", "text-green-400"},
		{"stop", "text-orange-400"},
		{"restart", "text-cyan-400"},
		{"security_scan", "text-purple-400"},
		{"unknown", "text-gray-400"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := auditActionColor(tt.action)
			if got != tt.want {
				t.Errorf("auditActionColor(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestIsHighRiskAction(t *testing.T) {
	highRisk := []string{"delete", "login_failed", "password_change", "password_reset",
		"api_key_create", "api_key_delete", "restore", "rollback"}
	lowRisk := []string{"login", "logout", "create", "update", "start", "stop", "restart", "view"}

	for _, action := range highRisk {
		t.Run("high_"+action, func(t *testing.T) {
			if !isHighRiskAction(action) {
				t.Errorf("isHighRiskAction(%q) should be true", action)
			}
		})
	}
	for _, action := range lowRisk {
		t.Run("low_"+action, func(t *testing.T) {
			if isHighRiskAction(action) {
				t.Errorf("isHighRiskAction(%q) should be false", action)
			}
		})
	}
}

// ============================================================================
// HTMX toast response tests (verifies error feedback to user)
// ============================================================================

func TestHTMXToastOnNilProxyService(t *testing.T) {
	h := newTestHandler()

	htmxTests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		params  map[string]string
	}{
		{"CertRenew", h.CertRenew, map[string]string{"id": "1"}},
		{"CertDelete", h.CertDelete, map[string]string{"id": "1"}},
		{"RedirDelete", h.RedirDelete, map[string]string{"id": "1"}},
		{"StreamDelete", h.StreamDelete, map[string]string{"id": "1"}},
		{"DeadDelete", h.DeadDelete, map[string]string{"id": "1"}},
		{"ACLDelete", h.ACLDelete, map[string]string{"id": "1"}},
	}

	for _, tt := range htmxTests {
		t.Run(tt.name+"_error_toast", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := requestWithChi("DELETE", "/proxy/test", tt.params)
			tt.handler(rec, req)

			trigger := rec.Header().Get("HX-Trigger")
			if trigger == "" {
				t.Error("expected HX-Trigger header")
			}
			if !strings.Contains(trigger, "showToast") {
				t.Errorf("HX-Trigger should contain showToast, got %q", trigger)
			}
			if !strings.Contains(trigger, "error") {
				t.Errorf("should contain error type, got %q", trigger)
			}
			if !strings.Contains(trigger, "not configured") {
				t.Errorf("should mention not configured, got %q", trigger)
			}
		})
	}
}

// ============================================================================
// Proxy ext helper tests
// ============================================================================

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single", "example.com", []string{"example.com"}},
		{"multiple", "a.com, b.com, c.com", []string{"a.com", "b.com", "c.com"}},
		{"extra_spaces", "  a.com , b.com  ", []string{"a.com", "b.com"}},
		{"empty_parts", "a.com,,b.com,", []string{"a.com", "b.com"}},
		{"all_empty", ",,,", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitAndTrim(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitAndTrim(%q) len = %d, want %d", tt.input, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCertViewToTempl(t *testing.T) {
	t.Run("valid_cert", func(t *testing.T) {
		cv := CertificateView{
			ID:          42,
			NiceName:    "Test Cert",
			Provider:    "letsencrypt",
			DomainNames: []string{"example.com"},
			ExpiresOn:   "2027-06-15T00:00:00Z",
		}
		result := certViewToTempl(cv)
		if result.ID != 42 {
			t.Errorf("ID = %d, want 42", result.ID)
		}
		if result.IsExpired {
			t.Error("should not be expired")
		}
		if result.DaysLeft <= 0 {
			t.Errorf("DaysLeft = %d, want positive", result.DaysLeft)
		}
	})

	t.Run("expired_cert", func(t *testing.T) {
		cv := CertificateView{ID: 1, ExpiresOn: "2020-01-01T00:00:00Z"}
		result := certViewToTempl(cv)
		if !result.IsExpired {
			t.Error("should be expired")
		}
	})

	t.Run("empty_expiry", func(t *testing.T) {
		cv := CertificateView{ID: 1}
		result := certViewToTempl(cv)
		if result.DaysLeft != 0 {
			t.Errorf("DaysLeft = %d, want 0", result.DaysLeft)
		}
	})
}

func TestParseACLForm(t *testing.T) {
	t.Run("complete_form", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/",
			strings.NewReader("name=test-acl&satisfy_any=on&pass_auth=on&auth_username[]=user1&auth_password[]=pass1&client_address[]=10.0.0.0/8"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()

		result := parseACLForm(req)
		if result.Name != "test-acl" {
			t.Errorf("Name = %q, want %q", result.Name, "test-acl")
		}
		if !result.SatisfyAny {
			t.Error("SatisfyAny should be true")
		}
		if len(result.Items) != 1 {
			t.Fatalf("Items: got %d, want 1", len(result.Items))
		}
		if result.Items[0].Username != "user1" {
			t.Errorf("Username = %q, want %q", result.Items[0].Username, "user1")
		}
		if len(result.Clients) != 1 {
			t.Fatalf("Clients: got %d, want 1", len(result.Clients))
		}
	})

	t.Run("empty_username_skipped", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/",
			strings.NewReader("name=test&auth_username[]=&auth_password[]=pass"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		result := parseACLForm(req)
		if len(result.Items) != 0 {
			t.Errorf("Items: got %d, want 0", len(result.Items))
		}
	})
}

// ============================================================================
// Redirect on nil proxy service (form-based handlers)
// ============================================================================

func TestProxyFormHandlers_RedirectOnNil(t *testing.T) {
	h := newTestHandler()

	formTests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		form    string
		params  map[string]string
	}{
		{"CertCreateLE", h.CertCreateLE, "/proxy/certificates/new/letsencrypt", "domain_names=example.com&email=a@b.com", nil},
		{"RedirCreate", h.RedirCreate, "/proxy/redirections", "domain_names=example.com&forward_scheme=http&forward_domain=localhost", nil},
		{"StreamCreate", h.StreamCreate, "/proxy/streams", "incoming_port=80&forwarding_host=localhost&forwarding_port=8080", nil},
		{"DeadCreate", h.DeadCreate, "/proxy/dead-hosts", "domain_names=example.com", nil},
		{"ACLCreate", h.ACLCreate, "/proxy/access-lists", "name=test", nil},
		{"RedirUpdate", h.RedirUpdate, "/proxy/redirections/1", "domain_names=example.com", map[string]string{"id": "1"}},
		{"StreamUpdate", h.StreamUpdate, "/proxy/streams/1", "incoming_port=80", map[string]string{"id": "1"}},
		{"ACLUpdate", h.ACLUpdate, "/proxy/access-lists/1", "name=test", map[string]string{"id": "1"}},
	}

	for _, tt := range formTests {
		t.Run(tt.name+"_redirect_on_nil", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := requestWithForm(tt.path, tt.form, tt.params)
			assertNoPanic(t, tt.name, func() {
				tt.handler(rec, req)
			})
			assertStatusCode(t, tt.name, rec, http.StatusSeeOther)
		})
	}
}
