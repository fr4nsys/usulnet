// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

type mockKeyRepo struct {
	keys          map[uuid.UUID]*models.SSHKey
	byFingerprint map[string]*models.SSHKey
	createErr     error
	lastUsed      map[uuid.UUID]time.Time
}

func newMockKeyRepo() *mockKeyRepo {
	return &mockKeyRepo{
		keys:          make(map[uuid.UUID]*models.SSHKey),
		byFingerprint: make(map[string]*models.SSHKey),
		lastUsed:      make(map[uuid.UUID]time.Time),
	}
}

func (r *mockKeyRepo) Create(_ context.Context, key *models.SSHKey) error {
	if r.createErr != nil {
		return r.createErr
	}
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}
	r.keys[key.ID] = key
	if key.Fingerprint != "" {
		r.byFingerprint[key.Fingerprint] = key
	}
	return nil
}

func (r *mockKeyRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SSHKey, error) {
	if k, ok := r.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

func (r *mockKeyRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.SSHKey, error) {
	var result []*models.SSHKey
	for _, k := range r.keys {
		if k.CreatedBy == userID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (r *mockKeyRepo) Update(_ context.Context, key *models.SSHKey) error {
	r.keys[key.ID] = key
	return nil
}

func (r *mockKeyRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := r.keys[id]; !ok {
		return errors.New("key not found")
	}
	delete(r.keys, id)
	return nil
}

func (r *mockKeyRepo) UpdateLastUsed(_ context.Context, id uuid.UUID) error {
	r.lastUsed[id] = time.Now()
	return nil
}

func (r *mockKeyRepo) GetByFingerprint(_ context.Context, fp string) (*models.SSHKey, error) {
	if k, ok := r.byFingerprint[fp]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

type mockConnRepo struct {
	conns     map[uuid.UUID]*models.SSHConnection
	createErr error
	statuses  map[uuid.UUID]models.SSHConnectionStatus
}

func newMockConnRepo() *mockConnRepo {
	return &mockConnRepo{
		conns:    make(map[uuid.UUID]*models.SSHConnection),
		statuses: make(map[uuid.UUID]models.SSHConnectionStatus),
	}
}

func (r *mockConnRepo) Create(_ context.Context, conn *models.SSHConnection) error {
	if r.createErr != nil {
		return r.createErr
	}
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SSHConnection, error) {
	if c, ok := r.conns[id]; ok {
		return c, nil
	}
	return nil, errors.New("connection not found")
}

func (r *mockConnRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.SSHConnection, error) {
	var result []*models.SSHConnection
	for _, c := range r.conns {
		if c.CreatedBy == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *mockConnRepo) ListByCategory(_ context.Context, userID uuid.UUID, cat string) ([]*models.SSHConnection, error) {
	var result []*models.SSHConnection
	for _, c := range r.conns {
		if c.CreatedBy == userID && c.Category == cat {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *mockConnRepo) Update(_ context.Context, conn *models.SSHConnection) error {
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := r.conns[id]; !ok {
		return errors.New("connection not found")
	}
	delete(r.conns, id)
	return nil
}

func (r *mockConnRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.SSHConnectionStatus, _ string) error {
	r.statuses[id] = status
	return nil
}

func (r *mockConnRepo) GetCategories(_ context.Context, userID uuid.UUID) ([]string, error) {
	catSet := make(map[string]bool)
	for _, c := range r.conns {
		if c.CreatedBy == userID && c.Category != "" {
			catSet[c.Category] = true
		}
	}
	var result []string
	for cat := range catSet {
		result = append(result, cat)
	}
	return result, nil
}

type mockSessionRepo struct {
	sessions []*models.SSHSession
}

func (r *mockSessionRepo) Create(_ context.Context, s *models.SSHSession) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	r.sessions = append(r.sessions, s)
	return nil
}

func (r *mockSessionRepo) End(_ context.Context, id uuid.UUID) error {
	for _, s := range r.sessions {
		if s.ID == id {
			now := time.Now()
			s.EndedAt = &now
			return nil
		}
	}
	return errors.New("session not found")
}

func (r *mockSessionRepo) ListByConnection(_ context.Context, connID uuid.UUID, limit int) ([]*models.SSHSession, error) {
	var result []*models.SSHSession
	for _, s := range r.sessions {
		if s.ConnectionID == connID {
			result = append(result, s)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (r *mockSessionRepo) ListActive(_ context.Context) ([]*models.SSHSession, error) {
	var result []*models.SSHSession
	for _, s := range r.sessions {
		if s.EndedAt == nil {
			result = append(result, s)
		}
	}
	return result, nil
}

type mockTunnelRepo struct {
	tunnels  map[uuid.UUID]*models.SSHTunnel
	statuses map[uuid.UUID]models.SSHTunnelStatus
}

func newMockTunnelRepo() *mockTunnelRepo {
	return &mockTunnelRepo{
		tunnels:  make(map[uuid.UUID]*models.SSHTunnel),
		statuses: make(map[uuid.UUID]models.SSHTunnelStatus),
	}
}

func (r *mockTunnelRepo) Create(_ context.Context, t *models.SSHTunnel) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	r.tunnels[t.ID] = t
	return nil
}

func (r *mockTunnelRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SSHTunnel, error) {
	if t, ok := r.tunnels[id]; ok {
		return t, nil
	}
	return nil, errors.New("tunnel not found")
}

func (r *mockTunnelRepo) ListByConnection(_ context.Context, connID uuid.UUID) ([]*models.SSHTunnel, error) {
	var result []*models.SSHTunnel
	for _, t := range r.tunnels {
		if t.ConnectionID == connID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (r *mockTunnelRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*models.SSHTunnel, error) {
	var result []*models.SSHTunnel
	for _, t := range r.tunnels {
		if t.UserID == userID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (r *mockTunnelRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.SSHTunnelStatus, _ string) error {
	r.statuses[id] = status
	return nil
}

func (r *mockTunnelRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.tunnels, id)
	return nil
}

type mockEncryptor struct{}

func (e *mockEncryptor) EncryptString(plaintext string) (string, error) {
	return "enc:" + plaintext, nil
}
func (e *mockEncryptor) DecryptString(ciphertext string) (string, error) {
	if len(ciphertext) > 4 && ciphertext[:4] == "enc:" {
		return ciphertext[4:], nil
	}
	return ciphertext, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *mockKeyRepo, *mockConnRepo, *mockSessionRepo, *mockTunnelRepo) {
	t.Helper()
	keyRepo := newMockKeyRepo()
	connRepo := newMockConnRepo()
	sessionRepo := &mockSessionRepo{}
	tunnelRepo := newMockTunnelRepo()

	svc := NewService(keyRepo, connRepo, sessionRepo, &mockEncryptor{}, logger.Nop())
	svc.SetTunnelRepo(tunnelRepo)

	return svc, keyRepo, connRepo, sessionRepo, tunnelRepo
}

// ---------------------------------------------------------------------------
// Tests: SSH Key Management
// ---------------------------------------------------------------------------

func TestGenerateKey_ED25519(t *testing.T) {
	svc, keyRepo, _, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	key, err := svc.GenerateKey(ctx, models.CreateSSHKeyInput{
		Name:    "test-key",
		KeyType: models.SSHKeyTypeED25519,
	}, userID)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.Name != "test-key" {
		t.Errorf("expected name test-key, got %s", key.Name)
	}
	if key.KeyType != models.SSHKeyTypeED25519 {
		t.Errorf("expected ED25519 type, got %s", key.KeyType)
	}
	if key.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if key.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	// Private key should be encrypted
	if key.PrivateKey == "" || key.PrivateKey[:4] != "enc:" {
		t.Error("expected encrypted private key")
	}
	if len(keyRepo.keys) != 1 {
		t.Errorf("expected 1 key in repo, got %d", len(keyRepo.keys))
	}
}

func TestGenerateKey_RSA(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	key, err := svc.GenerateKey(ctx, models.CreateSSHKeyInput{
		Name:    "rsa-key",
		KeyType: models.SSHKeyTypeRSA,
		KeyBits: 2048, // Use 2048 for faster tests
	}, userID)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}
	if key.KeyType != models.SSHKeyTypeRSA {
		t.Errorf("expected RSA type, got %s", key.KeyType)
	}
	if key.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
}

func TestGenerateKey_UnsupportedType(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.GenerateKey(ctx, models.CreateSSHKeyInput{
		Name:    "bad",
		KeyType: "dsa",
	}, uuid.New())
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestGenerateKey_RSA_DefaultBits(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	key, err := svc.GenerateKey(ctx, models.CreateSSHKeyInput{
		Name:    "rsa-default",
		KeyType: models.SSHKeyTypeRSA,
		// KeyBits is 0, should default to 4096
	}, uuid.New())
	if err != nil {
		t.Fatalf("GenerateKey with default bits failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestGetKey(t *testing.T) {
	svc, keyRepo, _, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	keyRepo.keys[id] = &models.SSHKey{ID: id, Name: "existing"}

	key, err := svc.GetKey(ctx, id)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.Name != "existing" {
		t.Errorf("expected name existing, got %s", key.Name)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.GetKey(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestListKeys(t *testing.T) {
	svc, keyRepo, _, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	keyRepo.keys[uuid.New()] = &models.SSHKey{ID: uuid.New(), Name: "k1", CreatedBy: userID}
	keyRepo.keys[uuid.New()] = &models.SSHKey{ID: uuid.New(), Name: "k2", CreatedBy: userID}
	keyRepo.keys[uuid.New()] = &models.SSHKey{ID: uuid.New(), Name: "other", CreatedBy: uuid.New()}

	keys, err := svc.ListKeys(ctx, userID)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys for user, got %d", len(keys))
	}
}

func TestDeleteKey(t *testing.T) {
	svc, keyRepo, _, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	keyRepo.keys[id] = &models.SSHKey{ID: id, Name: "doomed"}

	err := svc.DeleteKey(ctx, id)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if len(keyRepo.keys) != 0 {
		t.Error("expected key to be deleted")
	}
}

func TestDeleteKey_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	err := svc.DeleteKey(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

// ---------------------------------------------------------------------------
// Tests: SSH Connection Management
// ---------------------------------------------------------------------------

func TestCreateConnection_PasswordAuth(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	conn, err := svc.CreateConnection(ctx, models.CreateSSHConnectionInput{
		Name:     "test-server",
		Host:     "192.168.1.100",
		Port:     22,
		Username: "root",
		AuthType: models.SSHAuthPassword,
		Password: "secret",
		Category: "production",
	}, userID)
	if err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	if conn.Name != "test-server" {
		t.Errorf("expected name test-server, got %s", conn.Name)
	}
	if conn.Status != models.SSHConnectionUnknown {
		t.Errorf("expected unknown status, got %s", conn.Status)
	}
	// Password should be encrypted
	if conn.Password == "" || conn.Password == "secret" {
		t.Error("expected encrypted password, not plaintext")
	}
	if len(connRepo.conns) != 1 {
		t.Errorf("expected 1 connection in repo")
	}
}

func TestCreateConnection_KeyAuth(t *testing.T) {
	svc, keyRepo, _, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	keyID := uuid.New()
	keyRepo.keys[keyID] = &models.SSHKey{ID: keyID, Name: "my-key"}

	conn, err := svc.CreateConnection(ctx, models.CreateSSHConnectionInput{
		Name:     "key-server",
		Host:     "10.0.0.1",
		Port:     22,
		Username: "admin",
		AuthType: models.SSHAuthKey,
		KeyID:    &keyID,
	}, userID)
	if err != nil {
		t.Fatalf("CreateConnection with key failed: %v", err)
	}
	if conn.KeyID == nil || *conn.KeyID != keyID {
		t.Error("expected key ID to be set")
	}
}

func TestCreateConnection_KeyAuth_KeyNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	missingID := uuid.New()
	_, err := svc.CreateConnection(ctx, models.CreateSSHConnectionInput{
		Name:     "bad",
		Host:     "10.0.0.1",
		Port:     22,
		Username: "admin",
		AuthType: models.SSHAuthKey,
		KeyID:    &missingID,
	}, uuid.New())
	if err == nil {
		t.Error("expected error when key not found")
	}
}

func TestGetConnection(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.SSHConnection{ID: id, Name: "test", Host: "10.0.0.1"}

	conn, err := svc.GetConnection(ctx, id)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if conn.Name != "test" {
		t.Errorf("expected name test, got %s", conn.Name)
	}
}

func TestGetConnection_WithKey(t *testing.T) {
	svc, keyRepo, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	keyID := uuid.New()
	keyRepo.keys[keyID] = &models.SSHKey{ID: keyID, Name: "loaded-key"}

	connID := uuid.New()
	connRepo.conns[connID] = &models.SSHConnection{ID: connID, Name: "with-key", KeyID: &keyID}

	conn, err := svc.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if conn.Key == nil {
		t.Error("expected key to be loaded")
	}
	if conn.Key.Name != "loaded-key" {
		t.Errorf("expected key name loaded-key, got %s", conn.Key.Name)
	}
}

func TestUpdateConnection(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.SSHConnection{
		ID: id, Name: "old-name", Host: "10.0.0.1", Port: 22,
	}

	newName := "new-name"
	newHost := "10.0.0.2"
	conn, err := svc.UpdateConnection(ctx, id, models.UpdateSSHConnectionInput{
		Name: &newName,
		Host: &newHost,
	})
	if err != nil {
		t.Fatalf("UpdateConnection failed: %v", err)
	}
	if conn.Name != "new-name" {
		t.Errorf("expected updated name, got %s", conn.Name)
	}
	if conn.Host != "10.0.0.2" {
		t.Errorf("expected updated host, got %s", conn.Host)
	}
}

func TestUpdateConnection_PartialUpdate(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.SSHConnection{
		ID: id, Name: "server", Host: "10.0.0.1", Port: 22, Username: "admin",
	}

	newPort := 2222
	conn, err := svc.UpdateConnection(ctx, id, models.UpdateSSHConnectionInput{
		Port: &newPort,
	})
	if err != nil {
		t.Fatalf("UpdateConnection failed: %v", err)
	}
	// Only port should change
	if conn.Port != 2222 {
		t.Errorf("expected port 2222, got %d", conn.Port)
	}
	if conn.Name != "server" {
		t.Error("name should not change")
	}
	if conn.Username != "admin" {
		t.Error("username should not change")
	}
}

func TestUpdateConnection_PasswordEncrypted(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.SSHConnection{ID: id, Name: "srv"}

	newPW := "newsecret"
	conn, err := svc.UpdateConnection(ctx, id, models.UpdateSSHConnectionInput{
		Password: &newPW,
	})
	if err != nil {
		t.Fatalf("UpdateConnection failed: %v", err)
	}
	if conn.Password == "newsecret" {
		t.Error("password should be encrypted, not plaintext")
	}
	if conn.Password != "enc:newsecret" {
		t.Errorf("expected enc:newsecret, got %s", conn.Password)
	}
}

func TestDeleteConnection(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.SSHConnection{ID: id}

	err := svc.DeleteConnection(ctx, id)
	if err != nil {
		t.Fatalf("DeleteConnection failed: %v", err)
	}
	if len(connRepo.conns) != 0 {
		t.Error("expected connection to be deleted")
	}
}

func TestListConnections(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	connRepo.conns[uuid.New()] = &models.SSHConnection{ID: uuid.New(), CreatedBy: userID}
	connRepo.conns[uuid.New()] = &models.SSHConnection{ID: uuid.New(), CreatedBy: userID}

	conns, err := svc.ListConnections(ctx, userID)
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestGetCategories(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	connRepo.conns[uuid.New()] = &models.SSHConnection{ID: uuid.New(), CreatedBy: userID, Category: "prod"}
	connRepo.conns[uuid.New()] = &models.SSHConnection{ID: uuid.New(), CreatedBy: userID, Category: "dev"}
	connRepo.conns[uuid.New()] = &models.SSHConnection{ID: uuid.New(), CreatedBy: userID, Category: "prod"} // duplicate

	cats, err := svc.GetCategories(ctx, userID)
	if err != nil {
		t.Fatalf("GetCategories failed: %v", err)
	}
	if len(cats) != 2 {
		t.Errorf("expected 2 unique categories, got %d: %v", len(cats), cats)
	}
}

// ---------------------------------------------------------------------------
// Tests: SSH Sessions
// ---------------------------------------------------------------------------

func TestEndSession(t *testing.T) {
	svc, _, _, sessionRepo, _ := newTestService(t)
	ctx := context.Background()

	sid := uuid.New()
	sessionRepo.sessions = append(sessionRepo.sessions, &models.SSHSession{ID: sid})

	err := svc.EndSession(ctx, sid)
	if err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}
	if sessionRepo.sessions[0].EndedAt == nil {
		t.Error("expected session to have EndedAt set")
	}
}

func TestGetActiveSessions(t *testing.T) {
	svc, _, _, sessionRepo, _ := newTestService(t)
	ctx := context.Background()

	now := time.Now()
	sessionRepo.sessions = []*models.SSHSession{
		{ID: uuid.New()},             // active (no EndedAt)
		{ID: uuid.New(), EndedAt: &now}, // ended
		{ID: uuid.New()},             // active
	}

	active, err := svc.GetActiveSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveSessions failed: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("expected 2 active sessions, got %d", len(active))
	}
}

// ---------------------------------------------------------------------------
// Tests: SSH Tunnel Management
// ---------------------------------------------------------------------------

func TestCreateTunnel(t *testing.T) {
	svc, _, connRepo, _, tunnelRepo := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	connID := uuid.New()
	connRepo.conns[connID] = &models.SSHConnection{ID: connID, CreatedBy: userID}

	tunnel, err := svc.CreateTunnel(ctx, models.CreateSSHTunnelInput{
		ConnectionID: connID,
		Type:         models.SSHTunnelTypeLocal,
		LocalHost:    "",
		LocalPort:    8080,
		RemoteHost:   "db.internal",
		RemotePort:   5432,
	}, userID)
	if err != nil {
		t.Fatalf("CreateTunnel failed: %v", err)
	}
	if tunnel.LocalHost != "127.0.0.1" {
		t.Errorf("expected default localhost, got %s", tunnel.LocalHost)
	}
	if tunnel.Status != models.SSHTunnelStatusStopped {
		t.Errorf("expected stopped status, got %s", tunnel.Status)
	}
	if len(tunnelRepo.tunnels) != 1 {
		t.Error("expected tunnel in repo")
	}
}

func TestCreateTunnel_AccessDenied(t *testing.T) {
	svc, _, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	ownerID := uuid.New()
	otherID := uuid.New()
	connID := uuid.New()
	connRepo.conns[connID] = &models.SSHConnection{ID: connID, CreatedBy: ownerID}

	_, err := svc.CreateTunnel(ctx, models.CreateSSHTunnelInput{
		ConnectionID: connID,
		Type:         models.SSHTunnelTypeLocal,
		LocalPort:    8080,
		RemotePort:   5432,
	}, otherID)
	if err == nil {
		t.Error("expected access denied error")
	}
	var appErr *apperrors.AppError
	if errors.As(err, &appErr) {
		if appErr.Code != apperrors.CodeForbidden {
			t.Errorf("expected Forbidden code, got %s", appErr.Code)
		}
	}
}

func TestCreateTunnel_NilRepo(t *testing.T) {
	keyRepo := newMockKeyRepo()
	connRepo := newMockConnRepo()
	sessionRepo := &mockSessionRepo{}
	svc := NewService(keyRepo, connRepo, sessionRepo, &mockEncryptor{}, logger.Nop())
	// Don't set tunnel repo

	_, err := svc.CreateTunnel(context.Background(), models.CreateSSHTunnelInput{}, uuid.New())
	if err == nil {
		t.Error("expected error when tunnel repo not configured")
	}
}

func TestDeleteTunnel(t *testing.T) {
	svc, _, connRepo, _, tunnelRepo := newTestService(t)
	ctx := context.Background()
	userID := uuid.New()

	connID := uuid.New()
	connRepo.conns[connID] = &models.SSHConnection{ID: connID, CreatedBy: userID}

	tunnelID := uuid.New()
	tunnelRepo.tunnels[tunnelID] = &models.SSHTunnel{ID: tunnelID, ConnectionID: connID}

	err := svc.DeleteTunnel(ctx, tunnelID)
	if err != nil {
		t.Fatalf("DeleteTunnel failed: %v", err)
	}
	if len(tunnelRepo.tunnels) != 0 {
		t.Error("expected tunnel to be deleted")
	}
}

func TestStopTunnel(t *testing.T) {
	svc, _, _, _, tunnelRepo := newTestService(t)
	ctx := context.Background()
	tunnelID := uuid.New()

	err := svc.StopTunnel(ctx, tunnelID)
	if err != nil {
		t.Fatalf("StopTunnel failed: %v", err)
	}
	if tunnelRepo.statuses[tunnelID] != models.SSHTunnelStatusStopped {
		t.Error("expected stopped status after StopTunnel")
	}
}

// ---------------------------------------------------------------------------
// Tests: Helper functions
// ---------------------------------------------------------------------------

func TestDetectKeyType(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	tests := []struct {
		pubKey   string
		expected models.SSHKeyType
	}{
		{"ssh-ed25519 AAAAC3Nz...", models.SSHKeyTypeED25519},
		{"ssh-rsa AAAAB3Nz...", models.SSHKeyTypeRSA},
		{"ecdsa-sha2-nistp256 AAAA...", models.SSHKeyTypeECDSA},
		{"something-unknown", models.SSHKeyTypeRSA}, // fallback
		{"short", models.SSHKeyTypeRSA},              // too short
	}
	for _, tt := range tests {
		got := svc.detectKeyType(tt.pubKey)
		if got != tt.expected {
			t.Errorf("detectKeyType(%q) = %s, want %s", tt.pubKey[:min(20, len(tt.pubKey))], got, tt.expected)
		}
	}
}

func TestCleanup(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	// Should not panic even with no active clients/tunnels
	svc.Cleanup()
}

func TestSetTunnelRepo(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	newRepo := newMockTunnelRepo()
	svc.SetTunnelRepo(newRepo)
	if svc.tunnelRepo != newRepo {
		t.Error("expected tunnel repo to be updated")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
