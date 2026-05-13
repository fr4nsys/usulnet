// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ---------------------------------------------------------------------------
// stubReconService
// ---------------------------------------------------------------------------

// stubReconService is a recon.Service test double. Each method records
// its inputs and returns a canned response. Anything left nil bubbles
// up a synthetic error so unexpected calls show up in tests.
type stubReconService struct {
	createTarget         func(context.Context, recon.CreateTargetInput) (*recon.Target, error)
	getTarget            func(context.Context, uuid.UUID) (*recon.Target, error)
	listTargets          func(context.Context, recon.ListTargetsFilter) ([]recon.Target, error)
	deleteTarget         func(context.Context, uuid.UUID) error
	startOwnershipProof  func(context.Context, uuid.UUID, recon.OwnershipMethod) (*recon.OwnershipProof, error)
	verifyOwnershipProof func(context.Context, uuid.UUID) (*recon.OwnershipProof, error)
	listProfiles         func(context.Context) ([]recon.Profile, error)
	getProfile           func(context.Context, uuid.UUID) (*recon.Profile, error)
	createProfile        func(context.Context, recon.CreateProfileInput) (*recon.Profile, error)
	updateProfile        func(context.Context, uuid.UUID, recon.UpdateProfileInput) (*recon.Profile, error)
	deleteProfile        func(context.Context, uuid.UUID) error
	startScan            func(context.Context, recon.StartScanInput) (*recon.Scan, error)
	getScan              func(context.Context, uuid.UUID) (*recon.Scan, error)
	listScans            func(context.Context, recon.ListScansFilter) ([]recon.Scan, error)
	cancelScan           func(context.Context, uuid.UUID) error
	listFindings         func(context.Context, recon.ListFindingsFilter) ([]recon.Finding, error)
	getScanSummary       func(context.Context, uuid.UUID) (*recon.ScanSummary, error)
}

func (s *stubReconService) CreateTarget(ctx context.Context, in recon.CreateTargetInput) (*recon.Target, error) {
	return s.createTarget(ctx, in)
}
func (s *stubReconService) GetTarget(ctx context.Context, id uuid.UUID) (*recon.Target, error) {
	return s.getTarget(ctx, id)
}
func (s *stubReconService) ListTargets(ctx context.Context, f recon.ListTargetsFilter) ([]recon.Target, error) {
	return s.listTargets(ctx, f)
}
func (s *stubReconService) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	return s.deleteTarget(ctx, id)
}
func (s *stubReconService) StartOwnershipProof(ctx context.Context, id uuid.UUID, m recon.OwnershipMethod) (*recon.OwnershipProof, error) {
	return s.startOwnershipProof(ctx, id, m)
}
func (s *stubReconService) VerifyOwnershipProof(ctx context.Context, id uuid.UUID) (*recon.OwnershipProof, error) {
	return s.verifyOwnershipProof(ctx, id)
}
func (s *stubReconService) ListProfiles(ctx context.Context) ([]recon.Profile, error) {
	return s.listProfiles(ctx)
}
func (s *stubReconService) GetProfile(ctx context.Context, id uuid.UUID) (*recon.Profile, error) {
	return s.getProfile(ctx, id)
}
func (s *stubReconService) CreateProfile(ctx context.Context, in recon.CreateProfileInput) (*recon.Profile, error) {
	return s.createProfile(ctx, in)
}
func (s *stubReconService) UpdateProfile(ctx context.Context, id uuid.UUID, in recon.UpdateProfileInput) (*recon.Profile, error) {
	return s.updateProfile(ctx, id, in)
}
func (s *stubReconService) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	return s.deleteProfile(ctx, id)
}
func (s *stubReconService) StartScan(ctx context.Context, in recon.StartScanInput) (*recon.Scan, error) {
	return s.startScan(ctx, in)
}
func (s *stubReconService) GetScan(ctx context.Context, id uuid.UUID) (*recon.Scan, error) {
	return s.getScan(ctx, id)
}
func (s *stubReconService) ListScans(ctx context.Context, f recon.ListScansFilter) ([]recon.Scan, error) {
	return s.listScans(ctx, f)
}
func (s *stubReconService) CancelScan(ctx context.Context, id uuid.UUID) error {
	return s.cancelScan(ctx, id)
}
func (s *stubReconService) ListFindings(ctx context.Context, f recon.ListFindingsFilter) ([]recon.Finding, error) {
	return s.listFindings(ctx, f)
}
func (s *stubReconService) GetScanSummary(ctx context.Context, id uuid.UUID) (*recon.ScanSummary, error) {
	return s.getScanSummary(ctx, id)
}

// ---------------------------------------------------------------------------
// Stub connector service + canned data builders
// ---------------------------------------------------------------------------

type stubConnectorService struct {
	list func(context.Context) ([]handlers.ReconConnectorInfo, error)
	set  func(context.Context, string, map[string]string, bool) error
	del  func(context.Context, string) error
}

func (s *stubConnectorService) ListConnectors(ctx context.Context) ([]handlers.ReconConnectorInfo, error) {
	return s.list(ctx)
}
func (s *stubConnectorService) SetConnector(ctx context.Context, kind string, creds map[string]string, enabled bool) error {
	return s.set(ctx, kind, creds, enabled)
}
func (s *stubConnectorService) DeleteConnector(ctx context.Context, kind string) error {
	if s.del == nil {
		return nil
	}
	return s.del(ctx, kind)
}

// ---------------------------------------------------------------------------
// Test router setup
// ---------------------------------------------------------------------------

type reconTestEnv struct {
	router chi.Router
	svc    *stubReconService
	conns  *stubConnectorService
	ack    *handlers.MemoryAckStore
}

func newReconEnv(t *testing.T, opts reconEnvOpts) *reconTestEnv {
	t.Helper()

	svc := &stubReconService{}
	conns := &stubConnectorService{
		list: func(_ context.Context) ([]handlers.ReconConnectorInfo, error) {
			return []handlers.ReconConnectorInfo{{Kind: "hibp", Enabled: false}}, nil
		},
		set: func(_ context.Context, _ string, _ map[string]string, _ bool) error { return nil },
	}

	ack := handlers.NewMemoryAckStore()
	if opts.acknowledged {
		_ = ack.Acknowledge(context.Background(), nil, "test")
	}

	reconH := handlers.NewReconHandler(svc, conns, ack, logger.Nop())
	metaH := handlers.NewMetadataHandler(nil, handlers.DefaultMetadataUploadLimits(), logger.Nop())

	cfg := api.RouterConfig{
		JWTSecret:          testJWTSecret,
		CORSConfig:         middleware.DefaultCORSConfig(),
		RateLimitPerMinute: 10_000,
		RequestTimeout:     5 * time.Second,
		MetricsEnabled:     false,
		ReconEnabled:       opts.enabled,
		ReconAckChecker:    ack,
	}

	h := &api.Handlers{
		Recon:    reconH,
		Metadata: metaH,
	}

	return &reconTestEnv{
		router: api.NewRouter(cfg, h),
		svc:    svc,
		conns:  conns,
		ack:    ack,
	}
}

type reconEnvOpts struct {
	enabled      bool
	acknowledged bool
}

func defaultEnv(t *testing.T) *reconTestEnv {
	return newReconEnv(t, reconEnvOpts{enabled: true, acknowledged: true})
}

// canned data ---------------------------------------------------------------

func sampleTarget() *recon.Target {
	id := uuid.New()
	return &recon.Target{
		ID:        id,
		Type:      recon.TargetDomain,
		Value:     "example.com",
		Label:     "primary",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func sampleScan(targetID, profileID uuid.UUID) *recon.Scan {
	return &recon.Scan{
		ID:        uuid.New(),
		TargetID:  targetID,
		ProfileID: profileID,
		Status:    recon.ScanQueued,
		Engine:    "spiderfoot",
		CreatedAt: time.Now().UTC(),
	}
}

// ===========================================================================
// Acknowledgement / feature flag
// ===========================================================================

func TestRecon_FeatureFlagDisabled_AllRoutes404(t *testing.T) {
	env := newReconEnv(t, reconEnvOpts{enabled: false, acknowledged: true})
	tok := generateTestToken(t, testUser(), "alice", "admin")

	cases := []struct {
		method, path string
	}{
		{"GET", "/api/v1/recon/targets"},
		{"POST", "/api/v1/recon/targets"},
		{"GET", "/api/v1/recon/targets/" + uuid.NewString()},
		{"DELETE", "/api/v1/recon/targets/" + uuid.NewString()},
		{"POST", "/api/v1/recon/targets/" + uuid.NewString() + "/ownership/verify"},
		{"GET", "/api/v1/recon/profiles"},
		{"POST", "/api/v1/recon/profiles"},
		{"PUT", "/api/v1/recon/profiles/" + uuid.NewString()},
		{"DELETE", "/api/v1/recon/profiles/" + uuid.NewString()},
		{"GET", "/api/v1/recon/scans"},
		{"POST", "/api/v1/recon/scans"},
		{"GET", "/api/v1/recon/scans/" + uuid.NewString()},
		{"DELETE", "/api/v1/recon/scans/" + uuid.NewString()},
		{"GET", "/api/v1/recon/scans/" + uuid.NewString() + "/findings"},
		{"GET", "/api/v1/recon/scans/" + uuid.NewString() + "/report.json"},
		{"GET", "/api/v1/recon/scans/" + uuid.NewString() + "/report.csv"},
		{"GET", "/api/v1/recon/scans/" + uuid.NewString() + "/report.pdf"},
		{"GET", "/api/v1/recon/connectors"},
		{"PUT", "/api/v1/recon/connectors/hibp"},
		{"POST", "/api/v1/recon/_ack"},
		{"POST", "/api/v1/metadata/jobs"},
		{"GET", "/api/v1/metadata/jobs"},
		{"GET", "/api/v1/metadata/jobs/" + uuid.NewString()},
		{"GET", "/api/v1/metadata/jobs/" + uuid.NewString() + "/artifacts/" + uuid.NewString() + "/stripped"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			w := doRequest(t, env.router, c.method, c.path, "", tok)
			if w.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d. Body: %s", w.Code, w.Body.String())
			}
			assertErrorCode(t, w, "module_disabled")
		})
	}
}

func TestRecon_AckRequired_GatedRoutesReturn409(t *testing.T) {
	env := newReconEnv(t, reconEnvOpts{enabled: true, acknowledged: false})
	tok := generateTestToken(t, testUser(), "alice", "admin")

	gated := []struct {
		method, path string
	}{
		{"GET", "/api/v1/recon/targets"},
		{"GET", "/api/v1/recon/profiles"},
		{"GET", "/api/v1/recon/scans"},
		{"GET", "/api/v1/recon/connectors"},
		{"GET", "/api/v1/metadata/jobs"},
	}
	for _, c := range gated {
		c := c
		t.Run("gated "+c.path, func(t *testing.T) {
			w := doRequest(t, env.router, c.method, c.path, "", tok)
			if w.Code != http.StatusConflict {
				t.Fatalf("expected 409, got %d. Body: %s", w.Code, w.Body.String())
			}
			assertErrorCode(t, w, "acknowledgement_required")
		})
	}
}

func TestRecon_AckEndpoint_ExemptFromAckMiddleware(t *testing.T) {
	env := newReconEnv(t, reconEnvOpts{enabled: true, acknowledged: false})
	tok := generateTestToken(t, testUser(), "alice", "admin")

	w := doRequest(t, env.router, "POST", "/api/v1/recon/_ack", "", tok)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Subsequent gated calls succeed.
	env.svc.listProfiles = func(_ context.Context) ([]recon.Profile, error) {
		return []recon.Profile{}, nil
	}
	w = doRequest(t, env.router, "GET", "/api/v1/recon/profiles", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after ack, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestRecon_AckEndpoint_NonAdminDenied(t *testing.T) {
	env := newReconEnv(t, reconEnvOpts{enabled: true, acknowledged: false})
	tok := generateTestToken(t, testUser(), "bob", "operator")

	w := doRequest(t, env.router, "POST", "/api/v1/recon/_ack", "", tok)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	_ = env
}

func TestRecon_Unauthenticated_AllRoutes401(t *testing.T) {
	env := defaultEnv(t)

	w := doRequest(t, env.router, "GET", "/api/v1/recon/targets", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}
}

// ===========================================================================
// Targets
// ===========================================================================

func TestRecon_CreateTarget(t *testing.T) {
	env := defaultEnv(t)
	var called atomic.Int32
	env.svc.createTarget = func(_ context.Context, in recon.CreateTargetInput) (*recon.Target, error) {
		called.Add(1)
		if in.Type != recon.TargetDomain || in.Value != "example.com" {
			t.Errorf("unexpected input: %+v", in)
		}
		return sampleTarget(), nil
	}
	body := `{"type":"domain","value":"example.com","label":"primary"}`

	t.Run("operator happy path", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets", body, tok)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d. Body: %s", w.Code, w.Body.String())
		}
		if called.Load() != 1 {
			t.Fatalf("service not called")
		}
	})

	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets", body, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("validation failure", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets",
			`{"type":"bogus","value":"x"}`, tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets", body, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestRecon_ListTargets(t *testing.T) {
	env := defaultEnv(t)
	env.svc.listTargets = func(_ context.Context, _ recon.ListTargetsFilter) ([]recon.Target, error) {
		return []recon.Target{*sampleTarget()}, nil
	}

	t.Run("viewer happy path", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets", "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("admin happy path", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets", "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for admin, got %d", w.Code)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets", "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestRecon_GetTarget(t *testing.T) {
	env := defaultEnv(t)
	tgt := sampleTarget()
	env.svc.getTarget = func(_ context.Context, id uuid.UUID) (*recon.Target, error) {
		if id != tgt.ID {
			t.Errorf("unexpected id %s", id)
		}
		return tgt, nil
	}
	tok := generateTestToken(t, testUser(), "vic", "viewer")

	t.Run("happy", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets/"+tgt.ID.String(), "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
	t.Run("invalid id", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets/not-a-uuid", "", tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/recon/targets/"+tgt.ID.String(), "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestRecon_DeleteTarget(t *testing.T) {
	env := defaultEnv(t)
	tgt := sampleTarget()
	env.svc.deleteTarget = func(_ context.Context, id uuid.UUID) error {
		if id != tgt.ID {
			t.Errorf("unexpected id")
		}
		return nil
	}

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/targets/"+tgt.ID.String(), "", tok)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})
	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/targets/"+tgt.ID.String(), "", tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

func TestRecon_VerifyOwnership(t *testing.T) {
	env := defaultEnv(t)
	tgt := sampleTarget()
	proofID := uuid.New()
	verified := time.Now().UTC()
	env.svc.startOwnershipProof = func(_ context.Context, id uuid.UUID, m recon.OwnershipMethod) (*recon.OwnershipProof, error) {
		if id != tgt.ID || m != recon.OwnershipDNSTXT {
			t.Errorf("unexpected start: %s %s", id, m)
		}
		return &recon.OwnershipProof{ID: proofID, TargetID: tgt.ID, Method: m, Status: recon.OwnershipPending, Challenge: "usulnet-verify=abc", CreatedAt: time.Now().UTC()}, nil
	}
	env.svc.verifyOwnershipProof = func(_ context.Context, id uuid.UUID) (*recon.OwnershipProof, error) {
		if id != proofID {
			t.Errorf("unexpected verify id")
		}
		return &recon.OwnershipProof{ID: proofID, TargetID: tgt.ID, Method: recon.OwnershipDNSTXT, Status: recon.OwnershipVerified, VerifiedAt: &verified, CreatedAt: time.Now().UTC()}, nil
	}

	body := `{"method":"dns_txt"}`
	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets/"+tgt.ID.String()+"/ownership/verify", body, tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets/"+tgt.ID.String()+"/ownership/verify", body, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("validation failure", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/targets/"+tgt.ID.String()+"/ownership/verify",
			`{"method":"nope"}`, tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}

// ===========================================================================
// Profiles
// ===========================================================================

func TestRecon_ListProfiles(t *testing.T) {
	env := defaultEnv(t)
	env.svc.listProfiles = func(_ context.Context) ([]recon.Profile, error) {
		return []recon.Profile{{ID: uuid.New(), Name: "default", Kind: "passive", TargetTypes: []recon.TargetType{recon.TargetDomain}, CreatedAt: time.Now().UTC()}}, nil
	}
	t.Run("viewer happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "GET", "/api/v1/recon/profiles", "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		w := doRequest(t, env.router, "GET", "/api/v1/recon/profiles", "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestRecon_CreateProfile(t *testing.T) {
	env := defaultEnv(t)
	var captured recon.CreateProfileInput
	env.svc.createProfile = func(_ context.Context, in recon.CreateProfileInput) (*recon.Profile, error) {
		captured = in
		return &recon.Profile{
			ID: uuid.New(), Name: in.Name, Kind: "custom",
			TargetTypes: in.TargetTypes, Modules: in.Modules,
			CreatedAt: time.Now().UTC(),
		}, nil
	}
	body := `{"name":"custom-deep","target_types":["email"],"modules":["sfp_haveibeen"]}`

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/profiles", body, tok)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d. Body: %s", w.Code, w.Body.String())
		}
		if captured.Name != "custom-deep" {
			t.Errorf("captured Name = %q", captured.Name)
		}
	})
	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/profiles", body, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("validation: bad target_type", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/profiles",
			`{"name":"x","target_types":["bogus"],"modules":["sfp_haveibeen"]}`, tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
	t.Run("service rejects duplicate", func(t *testing.T) {
		env.svc.createProfile = func(_ context.Context, _ recon.CreateProfileInput) (*recon.Profile, error) {
			return nil, recon.ErrProfileExists
		}
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/profiles", body, tok)
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w.Code)
		}
	})
	t.Run("service rejects invalid module", func(t *testing.T) {
		env.svc.createProfile = func(_ context.Context, _ recon.CreateProfileInput) (*recon.Profile, error) {
			return nil, recon.ErrProfileInvalid
		}
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/profiles", body, tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}

func TestRecon_UpdateProfile(t *testing.T) {
	env := defaultEnv(t)
	profileID := uuid.New()
	env.svc.updateProfile = func(_ context.Context, id uuid.UUID, in recon.UpdateProfileInput) (*recon.Profile, error) {
		if id != profileID {
			t.Errorf("unexpected id: %s", id)
		}
		return &recon.Profile{
			ID: id, Name: in.Name, Kind: "custom",
			TargetTypes: in.TargetTypes, Modules: in.Modules,
			CreatedAt: time.Now().UTC(),
		}, nil
	}
	body := `{"name":"renamed","target_types":["email"],"modules":["sfp_haveibeen"]}`

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "PUT", "/api/v1/recon/profiles/"+profileID.String(), body, tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
	t.Run("builtin rejected", func(t *testing.T) {
		env.svc.updateProfile = func(_ context.Context, _ uuid.UUID, _ recon.UpdateProfileInput) (*recon.Profile, error) {
			return nil, recon.ErrProfileBuiltin
		}
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "PUT", "/api/v1/recon/profiles/"+profileID.String(), body, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("not found", func(t *testing.T) {
		env.svc.updateProfile = func(_ context.Context, _ uuid.UUID, _ recon.UpdateProfileInput) (*recon.Profile, error) {
			return nil, recon.ErrProfileNotFound
		}
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "PUT", "/api/v1/recon/profiles/"+profileID.String(), body, tok)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestRecon_DeleteProfile(t *testing.T) {
	env := defaultEnv(t)
	profileID := uuid.New()

	t.Run("admin happy", func(t *testing.T) {
		env.svc.deleteProfile = func(_ context.Context, id uuid.UUID) error {
			if id != profileID {
				t.Errorf("unexpected id")
			}
			return nil
		}
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/profiles/"+profileID.String(), "", tok)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})
	t.Run("operator denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "op", "operator")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/profiles/"+profileID.String(), "", tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("in use returns 409", func(t *testing.T) {
		env.svc.deleteProfile = func(_ context.Context, _ uuid.UUID) error {
			return recon.ErrProfileInUse
		}
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/profiles/"+profileID.String(), "", tok)
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w.Code)
		}
	})
	t.Run("builtin rejected", func(t *testing.T) {
		env.svc.deleteProfile = func(_ context.Context, _ uuid.UUID) error {
			return recon.ErrProfileBuiltin
		}
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/profiles/"+profileID.String(), "", tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

// ===========================================================================
// Scans
// ===========================================================================

func TestRecon_StartScan(t *testing.T) {
	env := defaultEnv(t)
	targetID := uuid.New()
	profileID := uuid.New()
	env.svc.startScan = func(_ context.Context, in recon.StartScanInput) (*recon.Scan, error) {
		if in.TargetID != targetID || in.ProfileID != profileID {
			t.Errorf("unexpected ids: %+v", in)
		}
		return sampleScan(in.TargetID, in.ProfileID), nil
	}
	body := `{"target_id":"` + targetID.String() + `","profile_id":"` + profileID.String() + `"}`

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/scans", body, tok)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/scans", body, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("validation failure", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "POST", "/api/v1/recon/scans", `{"target_id":"not-uuid","profile_id":"`+profileID.String()+`"}`, tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}

func TestRecon_ListScans(t *testing.T) {
	env := defaultEnv(t)
	env.svc.listScans = func(_ context.Context, _ recon.ListScansFilter) ([]recon.Scan, error) {
		return []recon.Scan{*sampleScan(uuid.New(), uuid.New())}, nil
	}

	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	w = doRequest(t, env.router, "GET", "/api/v1/recon/scans", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRecon_GetScan(t *testing.T) {
	env := defaultEnv(t)
	scan := sampleScan(uuid.New(), uuid.New())
	env.svc.getScan = func(_ context.Context, id uuid.UUID) (*recon.Scan, error) {
		if id != scan.ID {
			t.Errorf("unexpected id")
		}
		return scan, nil
	}
	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans/"+scan.ID.String(), "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRecon_CancelScan(t *testing.T) {
	env := defaultEnv(t)
	scan := sampleScan(uuid.New(), uuid.New())
	env.svc.cancelScan = func(_ context.Context, id uuid.UUID) error {
		if id != scan.ID {
			t.Errorf("unexpected id")
		}
		return nil
	}

	t.Run("operator happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "operator")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/scans/"+scan.ID.String(), "", tok)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})
	t.Run("viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "DELETE", "/api/v1/recon/scans/"+scan.ID.String(), "", tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

func TestRecon_ListFindings(t *testing.T) {
	env := defaultEnv(t)
	env.svc.listFindings = func(_ context.Context, f recon.ListFindingsFilter) ([]recon.Finding, error) {
		if f.ScanID == nil {
			t.Errorf("scan id filter missing")
		}
		return []recon.Finding{{ID: uuid.New(), Severity: recon.SeverityLow, FirstSeen: time.Now(), LastSeen: time.Now()}}, nil
	}
	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans/"+uuid.NewString()+"/findings", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// wireReportStubs programs the stub recon service with the four
// methods the report endpoints need: GetScan / GetTarget / GetProfile
// / GetScanSummary / ListFindings. Returns the canned scan/target/
// profile/findings so the test can assert on them.
func wireReportStubs(env *reconTestEnv) (uuid.UUID, *recon.Scan, *recon.Target, *recon.Profile, []recon.Finding) {
	scanID := uuid.New()
	targetID := uuid.New()
	profileID := uuid.New()
	now := time.Now().UTC()
	scan := &recon.Scan{
		ID: scanID, TargetID: targetID, ProfileID: profileID,
		Status: recon.ScanCompleted, Engine: "spiderfoot", CreatedAt: now,
	}
	target := &recon.Target{
		ID: targetID, Type: recon.TargetEmail,
		Value: "alice@example.com", CreatedAt: now, UpdatedAt: now,
	}
	profile := &recon.Profile{
		ID: profileID, Name: "email-exposure-lite",
		Modules: []string{"sfp_haveibeen"}, CreatedAt: now,
	}
	findings := []recon.Finding{{
		ID: uuid.New(), ScanID: scanID, TargetID: targetID,
		Module: "sfp_haveibeen", Category: "data_breach",
		Severity: recon.SeverityLow, Value: "Adobe",
		Confidence: 80, FirstSeen: now, LastSeen: now,
	}}

	env.svc.getScan = func(_ context.Context, _ uuid.UUID) (*recon.Scan, error) {
		return scan, nil
	}
	env.svc.getTarget = func(_ context.Context, id uuid.UUID) (*recon.Target, error) {
		return target, nil
	}
	env.svc.getProfile = func(_ context.Context, id uuid.UUID) (*recon.Profile, error) {
		return profile, nil
	}
	env.svc.getScanSummary = func(_ context.Context, _ uuid.UUID) (*recon.ScanSummary, error) {
		return &recon.ScanSummary{Counts: map[string]int{"low": 1}, Grade: "B", GeneratedAt: now}, nil
	}
	env.svc.listFindings = func(_ context.Context, _ recon.ListFindingsFilter) ([]recon.Finding, error) {
		return findings, nil
	}
	return scanID, scan, target, profile, findings
}

func TestRecon_ReportJSON(t *testing.T) {
	env := defaultEnv(t)
	scanID, _, _, _, _ := wireReportStubs(env)

	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans/"+scanID.String()+"/report.json", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing: %+v", body)
	}
	if summary["grade"] != "B" {
		t.Fatalf("grade != B: %+v", summary)
	}
	if _, ok := body["categories"].([]any); !ok {
		t.Fatalf("categories missing: %+v", body)
	}
	if body["scan_id"] != scanID.String() {
		t.Fatalf("scan_id = %v, want %s", body["scan_id"], scanID.String())
	}
}

func TestRecon_ReportCSV(t *testing.T) {
	env := defaultEnv(t)
	scanID, _, _, _, _ := wireReportStubs(env)

	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans/"+scanID.String()+"/report.csv", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !contains(ct, "text/csv") {
		t.Fatalf("expected text/csv, got %s", ct)
	}
	if !contains(w.Body.String(), "scan_id,target_id,target_type") {
		t.Fatalf("missing CSV header: %s", w.Body.String())
	}
}

func TestRecon_ReportPDF(t *testing.T) {
	env := defaultEnv(t)
	scanID, _, _, _, _ := wireReportStubs(env)

	tok := generateTestToken(t, testUser(), "vic", "viewer")
	w := doRequest(t, env.router, "GET", "/api/v1/recon/scans/"+scanID.String()+"/report.pdf", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q, want application/pdf", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !contains(cd, "scan-"+scanID.String()+".pdf") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	body := w.Body.Bytes()
	if len(body) < 200 || string(body[:5]) != "%PDF-" {
		t.Errorf("body is not a PDF (len=%d, prefix=%q)", len(body), body[:8])
	}
}

// ===========================================================================
// Connectors
// ===========================================================================

func TestRecon_Connectors(t *testing.T) {
	env := defaultEnv(t)

	t.Run("list admin", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "GET", "/api/v1/recon/connectors", "", tok)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
	t.Run("list operator denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "op", "operator")
		w := doRequest(t, env.router, "GET", "/api/v1/recon/connectors", "", tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
	t.Run("put admin happy", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "alice", "admin")
		w := doRequest(t, env.router, "PUT", "/api/v1/recon/connectors/hibp",
			`{"enabled":true,"credentials":{"api_key":"x"}}`, tok)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
	t.Run("put viewer denied", func(t *testing.T) {
		tok := generateTestToken(t, testUser(), "vic", "viewer")
		w := doRequest(t, env.router, "PUT", "/api/v1/recon/connectors/hibp", `{"enabled":true}`, tok)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

// ===========================================================================
// helpers
// ===========================================================================

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
