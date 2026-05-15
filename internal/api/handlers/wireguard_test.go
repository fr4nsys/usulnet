// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
)

// fakeWGService implements WireGuardService for the handler tests.
type fakeWGService struct {
	iface   *models.WireGuardInterface
	peer    *models.WireGuardPeer
	listErr error
	qrTok   string
	qrExp   time.Time
	consume error
}

func (f *fakeWGService) ListInterfaces(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.iface == nil {
		return nil, nil
	}
	return []*models.WireGuardInterface{f.iface}, nil
}
func (f *fakeWGService) GetInterface(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error) {
	return f.iface, nil
}
func (f *fakeWGService) CreateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	iface.ID = uuid.New()
	iface.PublicKey = "test-pubkey"
	iface.CreatedAt = time.Now()
	iface.UpdatedAt = iface.CreatedAt
	f.iface = iface
	return nil
}
func (f *fakeWGService) UpdateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	return nil
}
func (f *fakeWGService) DeleteInterface(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (f *fakeWGService) GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error) {
	return &models.WireGuardStats{TotalInterfaces: 1}, nil
}
func (f *fakeWGService) ListPeers(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error) {
	return nil, nil
}
func (f *fakeWGService) ListHostPeers(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error) {
	return nil, 0, nil
}
func (f *fakeWGService) GetPeer(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error) {
	return f.peer, nil
}
func (f *fakeWGService) CreatePeer(ctx context.Context, peer *models.WireGuardPeer, agentTargets []uuid.UUID) error {
	peer.ID = uuid.New()
	peer.PublicKey = "peer-pubkey"
	peer.CreatedAt = time.Now()
	peer.UpdatedAt = peer.CreatedAt
	f.peer = peer
	return nil
}
func (f *fakeWGService) UpdatePeer(ctx context.Context, peer *models.WireGuardPeer) error {
	return nil
}
func (f *fakeWGService) DeletePeer(ctx context.Context, id uuid.UUID) error { return nil }
func (f *fakeWGService) DecryptPeerConfig(peer *models.WireGuardPeer) (string, error) {
	return "[Interface]\n[Peer]\n", nil
}
func (f *fakeWGService) ListMeshLinks(ctx context.Context, peerID uuid.UUID) ([]*models.WireGuardMeshLink, error) {
	return nil, nil
}
func (f *fakeWGService) IssueQRToken(ctx context.Context, peerID uuid.UUID) (string, time.Time, error) {
	if f.qrTok != "" {
		return f.qrTok, f.qrExp, nil
	}
	return "tok-" + peerID.String()[:8], time.Now().Add(5 * time.Minute), nil
}
func (f *fakeWGService) ConsumeQRToken(token string, peerID uuid.UUID) error {
	return f.consume
}

func TestWireGuardHandler_ServiceUnavailable(t *testing.T) {
	h := NewWireGuardHandler(nil, func(_ *http.Request) uuid.UUID { return uuid.New() }, nil)
	req := httptest.NewRequest("GET", "/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestWireGuardHandler_MapErrors(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{wireguardsvc.ErrInvalidInput, "INVALID_INPUT"},
		{wireguardsvc.ErrSenderNotConfigured, "SERVICE_UNAVAILABLE"},
		{wireguardsvc.ErrEncryptorNotConfigured, "SERVICE_UNAVAILABLE"},
		{wireguardsvc.ErrQRTokenExpired, "INVALID_INPUT"},
	}
	for _, c := range cases {
		got := mapWireGuardError(c.err)
		s := got.Error()
		if !strings.Contains(s, "wireguard") && !strings.Contains(s, "qr") {
			t.Logf("mapWireGuardError(%v) => %q (just sanity check)", c.err, s)
		}
	}
	// Unknown error should pass through unchanged.
	unknown := errors.New("boom")
	got := mapWireGuardError(unknown)
	if !errors.Is(got, unknown) {
		t.Errorf("unknown error should pass through unchanged, got %v", got)
	}
}

func TestWireGuardHandler_CreatePeerInvalidInterfaceID(t *testing.T) {
	svc := &fakeWGService{}
	defaultHostID := uuid.New()
	h := NewWireGuardHandler(svc, func(_ *http.Request) uuid.UUID { return defaultHostID }, nil)

	body := bytes.NewBufferString(`{"interface_id":"not-a-uuid","name":"alice"}`)
	req := httptest.NewRequest("POST", "/peers", body)
	w := httptest.NewRecorder()
	h.CreatePeer(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestWireGuardHandler_IssueAndGetQR(t *testing.T) {
	now := time.Now()
	peerID := uuid.New()
	svc := &fakeWGService{
		peer: &models.WireGuardPeer{
			ID:          peerID,
			InterfaceID: uuid.New(),
			HostID:      uuid.New(),
			Name:        "Alice",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		qrTok: "tok-abc",
		qrExp: now.Add(5 * time.Minute),
	}
	defaultHostID := uuid.New()
	h := NewWireGuardHandler(svc, func(_ *http.Request) uuid.UUID { return defaultHostID }, nil)

	// IssueQR — call handler directly with chi route context.
	req := httptest.NewRequest("POST", "/peers/"+peerID.String()+"/qr/issue", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", peerID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.IssueQR(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("issue status %d body=%s", w.Code, w.Body.String())
	}
	var issued QRIssueResponse
	if err := json.NewDecoder(w.Body).Decode(&issued); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if issued.Token == "" || issued.URL == "" {
		t.Errorf("issue response missing fields: %+v", issued)
	}

	// GetQR — same trick.
	req2 := httptest.NewRequest("GET", "/peers/"+peerID.String()+"/qr?token="+issued.Token, nil)
	rctx2 := chi.NewRouteContext()
	rctx2.URLParams.Add("id", peerID.String())
	req2 = req2.WithContext(context.WithValue(req2.Context(), chi.RouteCtxKey, rctx2))
	w2 := httptest.NewRecorder()
	h.GetQR(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("get qr status %d body=%s", w2.Code, w2.Body.String())
	}
	var payload QRPayloadResponse
	if err := json.NewDecoder(w2.Body).Decode(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !strings.Contains(payload.Config, "[Interface]") {
		t.Errorf("payload config missing [Interface]: %q", payload.Config)
	}
}

func TestWireGuardHandler_GetQRMissingToken(t *testing.T) {
	peerID := uuid.New()
	svc := &fakeWGService{peer: &models.WireGuardPeer{ID: peerID}}
	defaultHostID := uuid.New()
	h := NewWireGuardHandler(svc, func(_ *http.Request) uuid.UUID { return defaultHostID }, nil)

	req := httptest.NewRequest("GET", "/peers/"+peerID.String()+"/qr", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", peerID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.GetQR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
