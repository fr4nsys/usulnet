// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// Test doubles
// ============================================================================

// fakeInterfaceRepo is an in-memory implementation of InterfaceRepository.
type fakeInterfaceRepo struct {
	mu        sync.Mutex
	rows      map[uuid.UUID]*models.WireGuardInterface
	createErr error
}

func newFakeInterfaceRepo() *fakeInterfaceRepo {
	return &fakeInterfaceRepo{rows: make(map[uuid.UUID]*models.WireGuardInterface)}
}

func (r *fakeInterfaceRepo) Create(_ context.Context, iface *models.WireGuardInterface) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createErr != nil {
		return r.createErr
	}
	if iface.ID == uuid.Nil {
		iface.ID = uuid.New()
	}
	iface.CreatedAt = time.Now()
	iface.UpdatedAt = iface.CreatedAt
	r.rows[iface.ID] = iface
	return nil
}

func (r *fakeInterfaceRepo) GetByID(_ context.Context, id uuid.UUID) (*models.WireGuardInterface, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *row
	return &cp, nil
}

func (r *fakeInterfaceRepo) Update(_ context.Context, iface *models.WireGuardInterface) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[iface.ID]; !ok {
		return errors.New("not found")
	}
	iface.UpdatedAt = time.Now()
	r.rows[iface.ID] = iface
	return nil
}

func (r *fakeInterfaceRepo) ListByHost(_ context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.WireGuardInterface, 0)
	for _, row := range r.rows {
		if row.HostID == hostID {
			cp := *row
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeInterfaceRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[id]; !ok {
		return errors.New("not found")
	}
	delete(r.rows, id)
	return nil
}

func (r *fakeInterfaceRepo) GetStats(_ context.Context, hostID uuid.UUID) (*models.WireGuardStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := &models.WireGuardStats{}
	for _, row := range r.rows {
		if row.HostID != hostID {
			continue
		}
		stats.TotalInterfaces++
		if row.Status == models.WGStatusActive {
			stats.ActiveInterfaces++
		}
		stats.TotalPeers += row.PeerCount
		stats.TotalRx += row.TransferRx
		stats.TotalTx += row.TransferTx
	}
	return stats, nil
}

// fakePeerRepo is an in-memory implementation of PeerRepository.
type fakePeerRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.WireGuardPeer
}

func newFakePeerRepo() *fakePeerRepo {
	return &fakePeerRepo{rows: make(map[uuid.UUID]*models.WireGuardPeer)}
}

func (r *fakePeerRepo) Create(_ context.Context, p *models.WireGuardPeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	r.rows[p.ID] = p
	return nil
}

func (r *fakePeerRepo) GetByID(_ context.Context, id uuid.UUID) (*models.WireGuardPeer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *row
	return &cp, nil
}

func (r *fakePeerRepo) Update(_ context.Context, p *models.WireGuardPeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[p.ID]; !ok {
		return errors.New("not found")
	}
	r.rows[p.ID] = p
	return nil
}

func (r *fakePeerRepo) ListByInterface(_ context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.WireGuardPeer, 0)
	for _, row := range r.rows {
		if row.InterfaceID == interfaceID {
			cp := *row
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakePeerRepo) ListByHost(_ context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := make([]*models.WireGuardPeer, 0)
	for _, row := range r.rows {
		if row.HostID == hostID {
			cp := *row
			all = append(all, &cp)
		}
	}
	total := len(all)
	if offset > total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (r *fakePeerRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[id]; !ok {
		return errors.New("not found")
	}
	delete(r.rows, id)
	return nil
}

func (r *fakePeerRepo) UpdateTransferStats(_ context.Context, id uuid.UUID, rx, tx int64, ts *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return errors.New("not found")
	}
	row.TransferRx = rx
	row.TransferTx = tx
	row.LastHandshake = ts
	return nil
}

// fakeMeshRepo is an in-memory implementation of MeshLinkRepository.
type fakeMeshRepo struct {
	mu    sync.Mutex
	links []*models.WireGuardMeshLink
}

func newFakeMeshRepo() *fakeMeshRepo {
	return &fakeMeshRepo{links: make([]*models.WireGuardMeshLink, 0)}
}

func (r *fakeMeshRepo) Upsert(_ context.Context, link *models.WireGuardMeshLink) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.links {
		if existing.PeerID == link.PeerID && existing.AgentHostID == link.AgentHostID {
			r.links[i] = link
			return nil
		}
	}
	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}
	r.links = append(r.links, link)
	return nil
}

func (r *fakeMeshRepo) ListByPeer(_ context.Context, peerID uuid.UUID) ([]*models.WireGuardMeshLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.WireGuardMeshLink, 0)
	for _, l := range r.links {
		if l.PeerID == peerID {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeMeshRepo) ListByAgent(_ context.Context, agentID uuid.UUID) ([]*models.WireGuardMeshLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.WireGuardMeshLink, 0)
	for _, l := range r.links {
		if l.AgentHostID == agentID {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeMeshRepo) ListAll(_ context.Context) ([]*models.WireGuardMeshLink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.WireGuardMeshLink, 0, len(r.links))
	for _, l := range r.links {
		cp := *l
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeMeshRepo) UpdateHandshake(_ context.Context, peerID, agentID uuid.UUID, ts time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.links {
		if l.PeerID == peerID && l.AgentHostID == agentID {
			t := ts
			l.LastHandshake = &t
			return nil
		}
	}
	return nil
}

// fakeEncryptor is a deterministic encryptor that prefixes ciphertext
// with "enc:" so the test can assert that ciphertext was actually used.
type fakeEncryptor struct{}

func (fakeEncryptor) EncryptString(s string) (string, error) {
	return "enc:" + base64.StdEncoding.EncodeToString([]byte(s)), nil
}

func (fakeEncryptor) DecryptString(c string) (string, error) {
	if !strings.HasPrefix(c, "enc:") {
		return "", errors.New("not encrypted")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c, "enc:"))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fakeSender records every command it receives and returns either a
// success or the configured error.
type fakeSender struct {
	mu      sync.Mutex
	calls   []*protocol.Command
	respErr error
}

func (s *fakeSender) SendCommand(_ context.Context, _ uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, cmd)
	if s.respErr != nil {
		return nil, s.respErr
	}
	return &protocol.CommandResult{Status: protocol.CommandStatusCompleted}, nil
}

// ============================================================================
// Tests
// ============================================================================

func newTestService(t *testing.T) (*Service, *fakeInterfaceRepo, *fakePeerRepo, *fakeMeshRepo) {
	t.Helper()
	ir := newFakeInterfaceRepo()
	pr := newFakePeerRepo()
	mr := newFakeMeshRepo()
	svc := NewService(ir, pr, mr, fakeEncryptor{}, nil)
	return svc, ir, pr, mr
}

func TestGenerateKeyPair_ProducesValidCurve25519(t *testing.T) {
	priv, pub, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	pb, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	if len(pb) != 32 {
		t.Errorf("priv key length = %d, want 32", len(pb))
	}
	// Curve25519 clamping rules.
	if pb[0]&7 != 0 {
		t.Errorf("priv key not clamped: low 3 bits = %b", pb[0]&7)
	}
	if pb[31]&0x80 != 0 {
		t.Errorf("priv key high bit set: %x", pb[31])
	}
	if pb[31]&0x40 == 0 {
		t.Errorf("priv key bit 6 not set: %x", pb[31])
	}

	pubB, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	if len(pubB) != 32 {
		t.Errorf("pub key length = %d, want 32", len(pubB))
	}
	// The placeholder XOR scheme of v26.2.7 would have produced a
	// public key that's the private key with the high byte flipped;
	// the real X25519 public key must NOT match that pattern.
	if pubB[0] == pb[0]^0xFF {
		t.Errorf("public key looks like v26.2.7 XOR placeholder")
	}
}

func TestGeneratePresharedKey_Random(t *testing.T) {
	a, err := generatePresharedKey()
	if err != nil {
		t.Fatalf("generatePresharedKey: %v", err)
	}
	b, err := generatePresharedKey()
	if err != nil {
		t.Fatalf("generatePresharedKey: %v", err)
	}
	if a == b {
		t.Errorf("preshared keys not random: both = %q", a)
	}
	bts, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(bts) != 32 {
		t.Errorf("psk not 32 bytes base64: len=%d err=%v", len(bts), err)
	}
}

func TestCreateInterface_GeneratesKeysAndEncryptsAtRest(t *testing.T) {
	svc, ir, _, _ := newTestService(t)
	ctx := context.Background()
	hostID := uuid.New()
	iface := &models.WireGuardInterface{
		HostID:      hostID,
		DisplayName: "Test VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	if iface.ID == uuid.Nil {
		t.Errorf("interface id not set")
	}
	if iface.PublicKey == "" {
		t.Errorf("public key not generated")
	}
	if !strings.HasPrefix(iface.PrivateKey, "enc:") {
		t.Errorf("private key not encrypted; got %q", iface.PrivateKey)
	}
	if iface.Name != "wg0" {
		t.Errorf("default name not applied: %q", iface.Name)
	}
	if iface.ListenPort != 51820 {
		t.Errorf("default port not applied: %d", iface.ListenPort)
	}
	if iface.MTU != 1420 {
		t.Errorf("default mtu not applied: %d", iface.MTU)
	}
	if iface.Status != models.WGStatusInactive {
		t.Errorf("initial status not inactive: %v", iface.Status)
	}
	// Re-load from repo: the stored copy must still be encrypted.
	got, err := ir.GetByID(ctx, iface.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !strings.HasPrefix(got.PrivateKey, "enc:") {
		t.Errorf("private key in repo not encrypted")
	}
}

func TestCreateInterface_RejectsMissingDisplayName(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	err := svc.CreateInterface(ctx, &models.WireGuardInterface{
		HostID:  uuid.New(),
		Address: "10.0.0.1/24",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateInterface_RejectsInvalidPort(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	err := svc.CreateInterface(ctx, &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "Bad",
		Address:     "10.0.0.1/24",
		ListenPort:  99999,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateInterface_RequiresEncryptor(t *testing.T) {
	ir := newFakeInterfaceRepo()
	pr := newFakePeerRepo()
	mr := newFakeMeshRepo()
	svc := NewService(ir, pr, mr, nil, nil)
	err := svc.CreateInterface(context.Background(), &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "Test",
		Address:     "10.0.0.1/24",
	})
	if !errors.Is(err, ErrEncryptorNotConfigured) {
		t.Errorf("expected ErrEncryptorNotConfigured, got %v", err)
	}
}

func TestDecryptInterface(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "Test",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	clear, err := svc.DecryptInterface(iface)
	if err != nil {
		t.Fatalf("DecryptInterface: %v", err)
	}
	if strings.HasPrefix(clear.PrivateKey, "enc:") {
		t.Errorf("decrypted private key still has cipher prefix")
	}
}

func TestCreatePeer_GeneratesAndEncryptsKeys(t *testing.T) {
	svc, _, pr, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
	}
	if err := svc.CreatePeer(ctx, peer, nil); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	if peer.PublicKey == "" {
		t.Errorf("public key not generated")
	}
	if !strings.HasPrefix(peer.PresharedKey, "enc:") {
		t.Errorf("preshared key not encrypted: %q", peer.PresharedKey)
	}
	if !strings.HasPrefix(peer.ConfigClient, "enc:") {
		t.Errorf("client config not encrypted: %q", peer.ConfigClient)
	}
	if peer.PersistentKeepalive != 25 {
		t.Errorf("default keepalive not applied: %d", peer.PersistentKeepalive)
	}
	// Reload from repo.
	got, err := pr.GetByID(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !strings.HasPrefix(got.PresharedKey, "enc:") {
		t.Errorf("repo psk not encrypted")
	}
}

func TestCreatePeer_RejectsMissingName(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	err := svc.CreatePeer(ctx, &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
	}, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestDecryptPeerConfig(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
		Endpoint:    "vpn.example.com",
	}
	if err := svc.CreatePeer(ctx, peer, nil); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	cfg, err := svc.DecryptPeerConfig(peer)
	if err != nil {
		t.Fatalf("DecryptPeerConfig: %v", err)
	}
	if !strings.Contains(cfg, "[Interface]") || !strings.Contains(cfg, "[Peer]") {
		t.Errorf("config missing sections: %q", cfg)
	}
	if !strings.Contains(cfg, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("client config missing AllowedIPs default: %q", cfg)
	}
	if !strings.Contains(cfg, "Endpoint = vpn.example.com:51820") {
		t.Errorf("endpoint not included: %q", cfg)
	}
}

func TestPropagatePeerToAgents_WithSender(t *testing.T) {
	svc, _, _, mr := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}

	sender := &fakeSender{}
	svc.SetCommandSender(sender)

	agentA := uuid.New()
	agentB := uuid.New()
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
	}
	if err := svc.CreatePeer(ctx, peer, []uuid.UUID{agentA, agentB}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	sender.mu.Lock()
	got := len(sender.calls)
	calls := append([]*protocol.Command(nil), sender.calls...)
	sender.mu.Unlock()
	if got != 2 {
		t.Errorf("expected 2 send calls, got %d", got)
	}
	for _, cmd := range calls {
		if cmd.Type != protocol.CmdWireGuardApplyPeer {
			t.Errorf("unexpected command type: %v", cmd.Type)
		}
		if cmd.Params.WireGuardInterface != "wg0" {
			t.Errorf("interface name not propagated: %q", cmd.Params.WireGuardInterface)
		}
		if !strings.Contains(cmd.Params.WireGuardPeer, peer.PublicKey) {
			t.Errorf("public key not in payload: %s", cmd.Params.WireGuardPeer)
		}
		if cmd.Timeout == 0 {
			t.Errorf("timeout not set on command")
		}
	}
	links, _ := mr.ListByPeer(ctx, peer.ID)
	if len(links) != 2 {
		t.Errorf("expected 2 mesh links, got %d", len(links))
	}
	for _, l := range links {
		if l.Status != models.WGMeshLinkApplied {
			t.Errorf("expected applied status, got %v", l.Status)
		}
	}
}

func TestPropagatePeerToAgents_SenderError_RecordsFailure(t *testing.T) {
	svc, _, _, mr := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}

	sender := &fakeSender{respErr: errors.New("agent unreachable")}
	svc.SetCommandSender(sender)
	agent := uuid.New()
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Bob",
		AllowedIPs:  "10.0.0.3/32",
	}
	if err := svc.CreatePeer(ctx, peer, []uuid.UUID{agent}); err != nil {
		t.Fatalf("CreatePeer should not return on agent error: %v", err)
	}
	links, _ := mr.ListByPeer(ctx, peer.ID)
	if len(links) != 1 {
		t.Fatalf("expected 1 mesh link, got %d", len(links))
	}
	if links[0].Status != models.WGMeshLinkFailed {
		t.Errorf("expected failed status, got %v", links[0].Status)
	}
	if links[0].LastError == "" {
		t.Errorf("last_error not populated")
	}
}

func TestPropagatePeerToAgents_NoSenderSkipsSilently(t *testing.T) {
	svc, _, _, mr := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
	}
	if err := svc.CreatePeer(ctx, peer, []uuid.UUID{uuid.New()}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	links, _ := mr.ListByPeer(ctx, peer.ID)
	if len(links) != 0 {
		t.Errorf("expected no mesh links when sender is nil, got %d", len(links))
	}
}

func TestIssueAndConsumeQRToken(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
	}
	if err := svc.CreatePeer(ctx, peer, nil); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	tok, exp, err := svc.IssueQRToken(ctx, peer.ID)
	if err != nil {
		t.Fatalf("IssueQRToken: %v", err)
	}
	if tok == "" {
		t.Errorf("empty token")
	}
	if time.Until(exp) > QRTTL+time.Second || time.Until(exp) < QRTTL-time.Second {
		t.Errorf("token expiry not within ~5min: %v", exp)
	}
	if err := svc.ConsumeQRToken(tok, peer.ID); err != nil {
		t.Errorf("first consume failed: %v", err)
	}
	if err := svc.ConsumeQRToken(tok, peer.ID); !errors.Is(err, ErrQRTokenExpired) {
		t.Errorf("token should be single-use; second consume got %v", err)
	}
}

func TestConsumeQRToken_WrongPeer(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
	}
	if err := svc.CreatePeer(ctx, peer, nil); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	tok, _, err := svc.IssueQRToken(ctx, peer.ID)
	if err != nil {
		t.Fatalf("IssueQRToken: %v", err)
	}
	err = svc.ConsumeQRToken(tok, uuid.New())
	if !errors.Is(err, ErrQRTokenExpired) {
		t.Errorf("expected ErrQRTokenExpired, got %v", err)
	}
}

func TestListInterfacesAndStats(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	hostID := uuid.New()
	for i := 0; i < 3; i++ {
		iface := &models.WireGuardInterface{
			HostID:      hostID,
			DisplayName: "VPN",
			Address:     "10.0.0.1/24",
		}
		if err := svc.CreateInterface(ctx, iface); err != nil {
			t.Fatalf("CreateInterface: %v", err)
		}
		// Vary the wg name so the unique index doesn't trip; the
		// fake repo doesn't enforce it but the production schema does.
		iface.Name = "wg" + string(rune('0'+i))
	}
	ifaces, err := svc.ListInterfaces(ctx, hostID)
	if err != nil {
		t.Fatalf("ListInterfaces: %v", err)
	}
	if len(ifaces) != 3 {
		t.Errorf("expected 3 interfaces, got %d", len(ifaces))
	}
	stats, err := svc.GetStats(ctx, hostID)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalInterfaces != 3 {
		t.Errorf("stats.TotalInterfaces = %d, want 3", stats.TotalInterfaces)
	}
}

func TestDeletePeer_TellsAgentsToRemove(t *testing.T) {
	svc, _, _, mr := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	sender := &fakeSender{}
	svc.SetCommandSender(sender)
	agent := uuid.New()
	peer := &models.WireGuardPeer{
		InterfaceID: iface.ID,
		HostID:      iface.HostID,
		Name:        "Alice",
		AllowedIPs:  "10.0.0.2/32",
	}
	if err := svc.CreatePeer(ctx, peer, []uuid.UUID{agent}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	sender.mu.Lock()
	applyCount := len(sender.calls)
	sender.mu.Unlock()
	if applyCount != 1 {
		t.Fatalf("expected 1 apply call, got %d", applyCount)
	}

	if err := svc.DeletePeer(ctx, peer.ID); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	sender.mu.Lock()
	got := len(sender.calls)
	last := sender.calls[len(sender.calls)-1]
	sender.mu.Unlock()
	if got != 2 {
		t.Errorf("expected 2 send calls after delete, got %d", got)
	}
	if last.Type != protocol.CmdWireGuardRemovePeer {
		t.Errorf("last command not remove_peer: %v", last.Type)
	}
	// The mesh-link rows live in mr until the next upsert; that's
	// acceptable — production cascades them via FK ON DELETE CASCADE.
	_ = mr
}

func TestProbeLocal(t *testing.T) {
	// We don't assume wg or wg-quick are installed in the test env;
	// the probe should simply report what it found without panicking.
	res := ProbeLocal(context.Background())
	_ = res.HasFullTooling()
}

func TestListHostPeers_PaginationDefaults(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	iface := &models.WireGuardInterface{
		HostID:      uuid.New(),
		DisplayName: "VPN",
		Address:     "10.0.0.1/24",
	}
	if err := svc.CreateInterface(ctx, iface); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	for i := 0; i < 5; i++ {
		peer := &models.WireGuardPeer{
			InterfaceID: iface.ID,
			HostID:      iface.HostID,
			Name:        "peer-" + string(rune('a'+i)),
			AllowedIPs:  "10.0.0.2/32",
		}
		if err := svc.CreatePeer(ctx, peer, nil); err != nil {
			t.Fatalf("CreatePeer: %v", err)
		}
	}
	peers, total, err := svc.ListHostPeers(ctx, iface.HostID, 0, -1)
	if err != nil {
		t.Fatalf("ListHostPeers: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(peers) != 5 {
		t.Errorf("len(peers) = %d, want 5 (limit default = 100)", len(peers))
	}
}
