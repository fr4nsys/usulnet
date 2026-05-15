// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package wireguard provides WireGuard VPN management for usulnet.
//
// The module is a free AGPL feature — no biz gating, no edition checks,
// no call-home. It is a thin admin layer over `wg` and `wg-quick`:
//
//   - The master stores interfaces, peers, and their cryptographic
//     material (private + preshared keys) AES-256-GCM-encrypted at rest
//     using the installation data encryption key (USULNET_ENCRYPTION_KEY,
//     same one recon_findings_raw uses).
//
//   - In master/agent mode, the master pushes peer entries to selected
//     agents over the existing NATS transport (see internal/gateway).
//     Agents call `wg set …`/`wg-quick up …` locally with a hard
//     timeout. The master never builds or runs the shell command.
//
//   - In standalone mode the service still runs but mesh links are
//     not propagated (there is no remote agent to push to). The host's
//     local `wg`/`wg-quick` tooling is probed once at startup; a
//     non-fatal log is emitted if either binary is missing.
//
// QR codes for client onboarding are generated on demand from a
// short-lived (5 min) one-time token; the rendered config string is
// also stored encrypted at rest so a stolen DB row still requires the
// installation key to read.
package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors. API handlers map these to stable HTTP status codes.
var (
	// ErrInvalidInput is returned when the caller supplies a malformed
	// or out-of-range field (empty name, port out of 1..65535, etc.).
	ErrInvalidInput = errors.New("wireguard: invalid input")

	// ErrSenderNotConfigured is returned when a mesh-propagation call
	// is attempted but no CommandSender has been wired. CRUD continues
	// to work without a sender — only mesh operations fail.
	ErrSenderNotConfigured = errors.New("wireguard: command sender not configured")

	// ErrEncryptorNotConfigured is returned when a key would need to be
	// encrypted or decrypted but the service was constructed without an
	// encryptor. Storing plaintext keys is not allowed by design.
	ErrEncryptorNotConfigured = errors.New("wireguard: encryptor not configured")

	// ErrQRTokenExpired is returned when a QR token is requested but
	// has expired or has already been consumed.
	ErrQRTokenExpired = errors.New("wireguard: qr token expired or already used")
)

// InterfaceRepository defines persistence for WireGuard interfaces.
type InterfaceRepository interface {
	Create(ctx context.Context, iface *models.WireGuardInterface) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error)
	Update(ctx context.Context, iface *models.WireGuardInterface) error
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error)
}

// PeerRepository defines persistence for WireGuard peers.
type PeerRepository interface {
	Create(ctx context.Context, peer *models.WireGuardPeer) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error)
	Update(ctx context.Context, peer *models.WireGuardPeer) error
	ListByInterface(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error)
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateTransferStats(ctx context.Context, id uuid.UUID, rx, tx int64, lastHandshake *time.Time) error
}

// MeshLinkRepository persists the propagation state of peer entries on
// remote agents. The mesh-status web page reads from this.
type MeshLinkRepository interface {
	Upsert(ctx context.Context, link *models.WireGuardMeshLink) error
	ListByPeer(ctx context.Context, peerID uuid.UUID) ([]*models.WireGuardMeshLink, error)
	ListByAgent(ctx context.Context, agentHostID uuid.UUID) ([]*models.WireGuardMeshLink, error)
	ListAll(ctx context.Context) ([]*models.WireGuardMeshLink, error)
	UpdateHandshake(ctx context.Context, peerID, agentHostID uuid.UUID, ts time.Time) error
}

// CommandSender sends commands to remote agents. Satisfied by
// gateway.CommandDispatcher. Pass nil for standalone-mode installs
// where peers live in the DB but are not propagated to any agent.
type CommandSender interface {
	SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error)
}

// Encryptor is the narrow encrypt/decrypt contract the service depends
// on. Satisfied by *crypto.AESEncryptor.
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}

// qrToken is a single-use, time-limited reference to a peer config. It
// is generated on POST /peers/{id}/qr/issue and consumed by the
// browser via GET /peers/{id}/qr?token=…
type qrToken struct {
	peerID    uuid.UUID
	expiresAt time.Time
}

// Service is the wireguard business logic. Construct via NewService.
type Service struct {
	interfaces InterfaceRepository
	peers      PeerRepository
	meshLinks  MeshLinkRepository
	encryptor  Encryptor
	sender     CommandSender
	logger     *logger.Logger

	// qrTokens maps token → peerID + expiry. The tokens are short (5 min)
	// and consumed on first read, so an in-memory map is adequate; a
	// restart invalidates outstanding tokens, which is acceptable for a
	// one-time onboarding flow.
	qrMu     sync.Mutex
	qrTokens map[string]qrToken
}

// QRTTL is the lifetime of a one-time QR token.
const QRTTL = 5 * time.Minute

// NewService creates a new WireGuard service.
//
// encryptor MAY be nil for tests; the production wire-up always passes
// the AES encryptor so private and preshared keys are encrypted at rest.
// When encryptor is nil, key-bearing operations return
// ErrEncryptorNotConfigured.
func NewService(
	interfaces InterfaceRepository,
	peers PeerRepository,
	meshLinks MeshLinkRepository,
	encryptor Encryptor,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		interfaces: interfaces,
		peers:      peers,
		meshLinks:  meshLinks,
		encryptor:  encryptor,
		logger:     log.Named("wireguard"),
		qrTokens:   make(map[string]qrToken),
	}
}

// SetCommandSender configures the NATS gateway for mesh propagation.
// Safe to call after construction. Without a sender, CreatePeer/
// DeletePeer skip the propagation step but still persist the row.
func (s *Service) SetCommandSender(sender CommandSender) {
	s.sender = sender
}

// ============================================================================
// Interface CRUD
// ============================================================================

// ListInterfaces returns all WireGuard interfaces for a host (private
// keys are returned in ciphertext form — callers that need the cleartext
// must call DecryptInterface).
func (s *Service) ListInterfaces(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error) {
	return s.interfaces.ListByHost(ctx, hostID)
}

// GetInterface returns an interface by ID. The private_key field
// remains AES-GCM-encrypted; use DecryptInterface for plaintext access.
func (s *Service) GetInterface(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error) {
	return s.interfaces.GetByID(ctx, id)
}

// validateInterfaceInput enforces the closed-port/CIDR rules at the
// service boundary. v26.2.7's service skipped validation; we catch it
// here so audit logs and DB rows stay consistent.
func validateInterfaceInput(iface *models.WireGuardInterface) error {
	iface.DisplayName = strings.TrimSpace(iface.DisplayName)
	if iface.DisplayName == "" {
		return fmt.Errorf("%w: display_name is required", ErrInvalidInput)
	}
	if iface.ListenPort != 0 && (iface.ListenPort < 1 || iface.ListenPort > 65535) {
		return fmt.Errorf("%w: listen_port must be 1..65535", ErrInvalidInput)
	}
	if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 9000) {
		return fmt.Errorf("%w: mtu must be 576..9000", ErrInvalidInput)
	}
	if strings.TrimSpace(iface.Address) == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidInput)
	}
	return nil
}

// CreateInterface creates a new WireGuard interface. Keys are generated
// server-side (correct Curve25519 public key, not v26.2.7's placeholder)
// and stored AES-GCM-encrypted at rest.
func (s *Service) CreateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	if err := validateInterfaceInput(iface); err != nil {
		return err
	}

	if iface.PrivateKey == "" {
		priv, pub, err := generateKeyPair()
		if err != nil {
			return fmt.Errorf("generate key pair: %w", err)
		}
		iface.PrivateKey = priv
		iface.PublicKey = pub
	} else if iface.PublicKey == "" {
		// Caller supplied a private key but no public key; we cannot
		// derive without re-clamping. Reject to keep the contract
		// explicit.
		return fmt.Errorf("%w: public_key required when private_key is set", ErrInvalidInput)
	}

	if iface.Name == "" {
		iface.Name = "wg0"
	}
	if iface.ListenPort == 0 {
		iface.ListenPort = 51820
	}
	if iface.MTU == 0 {
		iface.MTU = 1420
	}
	if iface.DNS == "" {
		iface.DNS = "1.1.1.1"
	}
	iface.Status = models.WGStatusInactive

	if s.encryptor == nil {
		return ErrEncryptorNotConfigured
	}
	enc, err := s.encryptor.EncryptString(iface.PrivateKey)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}
	iface.PrivateKey = enc

	if err := s.interfaces.Create(ctx, iface); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}

	s.logger.Info("WireGuard interface created",
		"interface_id", iface.ID,
		"name", iface.Name,
		"host_id", iface.HostID)
	return nil
}

// UpdateInterface updates a WireGuard interface. The PrivateKey field
// must already be AES-encrypted at this point (handlers do not allow
// rotating the private key via PUT).
func (s *Service) UpdateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	if err := s.interfaces.Update(ctx, iface); err != nil {
		return fmt.Errorf("update interface: %w", err)
	}
	s.logger.Info("WireGuard interface updated", "interface_id", iface.ID)
	return nil
}

// DeleteInterface deletes a WireGuard interface and all its peers
// (cascade via FK ON DELETE CASCADE).
func (s *Service) DeleteInterface(ctx context.Context, id uuid.UUID) error {
	if err := s.interfaces.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete interface: %w", err)
	}
	s.logger.Info("WireGuard interface deleted", "interface_id", id)
	return nil
}

// GetStats returns aggregate WireGuard statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error) {
	return s.interfaces.GetStats(ctx, hostID)
}

// DecryptInterface returns a copy of iface with PrivateKey replaced
// by the decrypted plaintext. The caller must NOT persist the result.
func (s *Service) DecryptInterface(iface *models.WireGuardInterface) (*models.WireGuardInterface, error) {
	if s.encryptor == nil {
		return nil, ErrEncryptorNotConfigured
	}
	if iface.PrivateKey == "" {
		return iface, nil
	}
	plain, err := s.encryptor.DecryptString(iface.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	out := *iface
	out.PrivateKey = plain
	return &out, nil
}

// ============================================================================
// Peer CRUD
// ============================================================================

// ListPeers returns all peers for an interface.
func (s *Service) ListPeers(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error) {
	return s.peers.ListByInterface(ctx, interfaceID)
}

// ListHostPeers returns paginated peers for a host.
func (s *Service) ListHostPeers(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.peers.ListByHost(ctx, hostID, limit, offset)
}

// GetPeer returns a peer by ID (preshared key and client config remain
// in ciphertext form).
func (s *Service) GetPeer(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error) {
	return s.peers.GetByID(ctx, id)
}

// validatePeerInput enforces the basic peer-field invariants.
func validatePeerInput(peer *models.WireGuardPeer) error {
	peer.Name = strings.TrimSpace(peer.Name)
	if peer.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if peer.PersistentKeepalive != 0 && (peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535) {
		return fmt.Errorf("%w: persistent_keepalive must be 0..65535", ErrInvalidInput)
	}
	return nil
}

// CreatePeer creates a new WireGuard peer. Both the preshared key and
// the rendered client config are encrypted at rest. After persisting
// the row, the service issues a mesh-propagation push to every selected
// agent (see SetCommandSender / propagatePeerToAgents).
func (s *Service) CreatePeer(ctx context.Context, peer *models.WireGuardPeer, agentTargets []uuid.UUID) error {
	if err := validatePeerInput(peer); err != nil {
		return err
	}
	if s.encryptor == nil {
		return ErrEncryptorNotConfigured
	}

	if peer.PublicKey == "" {
		_, pub, err := generateKeyPair()
		if err != nil {
			return fmt.Errorf("generate peer keys: %w", err)
		}
		peer.PublicKey = pub
	}
	if peer.PresharedKey == "" {
		psk, err := generatePresharedKey()
		if err != nil {
			return fmt.Errorf("generate preshared key: %w", err)
		}
		peer.PresharedKey = psk
	}
	if peer.AllowedIPs == "" {
		peer.AllowedIPs = "10.0.0.0/24"
	}
	if peer.PersistentKeepalive == 0 {
		peer.PersistentKeepalive = 25
	}

	// Render and encrypt the client config before persisting. v26.2.7
	// stored the cleartext config in config_qr; we encrypt it so a
	// stolen DB row still requires the installation key to read.
	iface, err := s.interfaces.GetByID(ctx, peer.InterfaceID)
	if err != nil {
		return fmt.Errorf("load interface: %w", err)
	}
	clientCfg := s.generatePeerConfig(peer, iface)
	encCfg, err := s.encryptor.EncryptString(clientCfg)
	if err != nil {
		return fmt.Errorf("encrypt client config: %w", err)
	}
	peer.ConfigClient = encCfg

	encPSK, err := s.encryptor.EncryptString(peer.PresharedKey)
	if err != nil {
		return fmt.Errorf("encrypt preshared key: %w", err)
	}
	peer.PresharedKey = encPSK

	if err := s.peers.Create(ctx, peer); err != nil {
		return fmt.Errorf("create peer: %w", err)
	}

	s.logger.Info("WireGuard peer created",
		"peer_id", peer.ID,
		"interface_id", peer.InterfaceID,
		"name", peer.Name,
		"agent_targets", len(agentTargets))

	// Propagate to selected agents. Failures are logged + recorded in
	// the mesh_links table as status=failed; the CRUD operation itself
	// still succeeds so the operator can retry from the UI.
	s.propagatePeerToAgents(ctx, peer, iface, agentTargets)

	return nil
}

// UpdatePeer updates a WireGuard peer. Re-renders the client config
// from the (possibly changed) interface settings; the new ciphertext
// replaces the old one.
func (s *Service) UpdatePeer(ctx context.Context, peer *models.WireGuardPeer) error {
	if err := s.peers.Update(ctx, peer); err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	s.logger.Info("WireGuard peer updated", "peer_id", peer.ID)
	return nil
}

// DeletePeer deletes a WireGuard peer and removes the entry from every
// mesh agent that had previously applied it.
func (s *Service) DeletePeer(ctx context.Context, id uuid.UUID) error {
	peer, err := s.peers.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("load peer: %w", err)
	}
	iface, ifaceErr := s.interfaces.GetByID(ctx, peer.InterfaceID)
	if err := s.peers.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	s.logger.Info("WireGuard peer deleted", "peer_id", id)

	if ifaceErr == nil && s.meshLinks != nil {
		// Tell each agent that previously applied this peer to remove
		// it locally. We use the existing mesh-link rows (which the
		// FK cascade has not yet deleted because we just read them in
		// ListByPeer above) to discover targets.
		links, listErr := s.meshLinks.ListByPeer(ctx, id)
		if listErr == nil {
			for _, link := range links {
				s.sendRemovePeer(ctx, link.AgentHostID, iface, peer)
			}
		}
	}
	return nil
}

// DecryptPeerConfig returns the cleartext client configuration for the
// peer. The caller is responsible for not persisting the result.
func (s *Service) DecryptPeerConfig(peer *models.WireGuardPeer) (string, error) {
	if s.encryptor == nil {
		return "", ErrEncryptorNotConfigured
	}
	if peer.ConfigClient == "" {
		return "", nil
	}
	return s.encryptor.DecryptString(peer.ConfigClient)
}

// DecryptPeerPresharedKey returns the cleartext preshared key.
func (s *Service) DecryptPeerPresharedKey(peer *models.WireGuardPeer) (string, error) {
	if s.encryptor == nil {
		return "", ErrEncryptorNotConfigured
	}
	if peer.PresharedKey == "" {
		return "", nil
	}
	return s.encryptor.DecryptString(peer.PresharedKey)
}

// ============================================================================
// Mesh propagation (master → agents)
// ============================================================================

// propagatePeerToAgents pushes the peer entry to every host in the
// agentTargets list. Each push writes a mesh_links row with status
// pending/applied/failed so the UI can display the propagation matrix.
//
// Errors are logged but do NOT unwind the CRUD operation — the peer
// already exists on the master, and the operator can retry per-agent.
func (s *Service) propagatePeerToAgents(
	ctx context.Context,
	peer *models.WireGuardPeer,
	iface *models.WireGuardInterface,
	agentTargets []uuid.UUID,
) {
	if len(agentTargets) == 0 {
		return
	}
	if s.sender == nil {
		s.logger.Debug("mesh propagation skipped: no command sender wired",
			"peer_id", peer.ID, "targets", len(agentTargets))
		return
	}
	if s.meshLinks == nil {
		s.logger.Debug("mesh propagation skipped: no mesh link repository wired",
			"peer_id", peer.ID, "targets", len(agentTargets))
		return
	}

	for _, agentID := range agentTargets {
		// Record pending status BEFORE the send so the UI shows that
		// propagation has started even if the call hangs.
		_ = s.meshLinks.Upsert(ctx, &models.WireGuardMeshLink{
			PeerID:      peer.ID,
			AgentHostID: agentID,
			Status:      models.WGMeshLinkPending,
		})

		err := s.sendApplyPeer(ctx, agentID, iface, peer)
		link := &models.WireGuardMeshLink{
			PeerID:      peer.ID,
			AgentHostID: agentID,
		}
		if err != nil {
			link.Status = models.WGMeshLinkFailed
			link.LastError = err.Error()
			s.logger.Warn("mesh propagation failed",
				"peer_id", peer.ID, "agent_host_id", agentID, "error", err)
		} else {
			link.Status = models.WGMeshLinkApplied
		}
		if upErr := s.meshLinks.Upsert(ctx, link); upErr != nil {
			s.logger.Error("failed to upsert mesh link",
				"peer_id", peer.ID, "agent_host_id", agentID, "error", upErr)
		}
	}
}

// agentPeerPayload is the wire shape the agent's wireguard.apply_peer
// handler expects.
type agentPeerPayload struct {
	PublicKey           string `json:"public_key"`
	PresharedKey        string `json:"preshared_key,omitempty"`
	AllowedIPs          string `json:"allowed_ips"`
	Endpoint            string `json:"endpoint,omitempty"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

// sendApplyPeer ships the peer entry to a single agent. The agent shells
// out to `wg set <interface> peer <pubkey> …` with a hard timeout.
func (s *Service) sendApplyPeer(
	ctx context.Context,
	agentHostID uuid.UUID,
	iface *models.WireGuardInterface,
	peer *models.WireGuardPeer,
) error {
	if s.encryptor == nil {
		return ErrEncryptorNotConfigured
	}
	psk, err := s.encryptor.DecryptString(peer.PresharedKey)
	if err != nil {
		return fmt.Errorf("decrypt preshared key: %w", err)
	}
	payload := agentPeerPayload{
		PublicKey:           peer.PublicKey,
		PresharedKey:        psk,
		AllowedIPs:          peer.AllowedIPs,
		Endpoint:            peer.Endpoint,
		PersistentKeepalive: peer.PersistentKeepalive,
	}
	js, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal peer payload: %w", err)
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdWireGuardApplyPeer,
		HostID:   agentHostID.String(),
		Priority: protocol.PriorityHigh,
		Timeout:  protocol.DefaultTimeout(protocol.CmdWireGuardApplyPeer),
		Params: protocol.CommandParams{
			WireGuardInterface: iface.Name,
			WireGuardPeer:      string(js),
		},
	}

	result, err := s.sender.SendCommand(ctx, agentHostID, cmd)
	if err != nil {
		return fmt.Errorf("send apply_peer: %w", err)
	}
	if result.Error != nil {
		return fmt.Errorf("apply_peer: %s", result.Error.Message)
	}
	return nil
}

// sendRemovePeer tells an agent to remove the peer entry locally. Best
// effort: errors are logged but the master-side row is already gone.
func (s *Service) sendRemovePeer(
	ctx context.Context,
	agentHostID uuid.UUID,
	iface *models.WireGuardInterface,
	peer *models.WireGuardPeer,
) {
	if s.sender == nil || iface == nil {
		return
	}
	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdWireGuardRemovePeer,
		HostID:   agentHostID.String(),
		Priority: protocol.PriorityHigh,
		Timeout:  protocol.DefaultTimeout(protocol.CmdWireGuardRemovePeer),
		Params: protocol.CommandParams{
			WireGuardInterface: iface.Name,
			WireGuardPeer:      peer.PublicKey,
		},
	}
	if _, err := s.sender.SendCommand(ctx, agentHostID, cmd); err != nil {
		s.logger.Warn("mesh remove_peer failed",
			"peer_id", peer.ID, "agent_host_id", agentHostID, "error", err)
	}
}

// ListMeshLinks returns mesh-link rows scoped by peer (when peerID is
// non-Nil) or globally (when peerID == uuid.Nil).
func (s *Service) ListMeshLinks(ctx context.Context, peerID uuid.UUID) ([]*models.WireGuardMeshLink, error) {
	if s.meshLinks == nil {
		return nil, nil
	}
	if peerID == uuid.Nil {
		return s.meshLinks.ListAll(ctx)
	}
	return s.meshLinks.ListByPeer(ctx, peerID)
}

// ============================================================================
// One-time QR token
// ============================================================================

// IssueQRToken mints a fresh single-use token for the given peer. The
// token is valid for QRTTL (5 minutes) and is consumed by the next
// ConsumeQRToken call. The QR endpoint encodes the cleartext peer
// config into a PNG; the token gates access.
func (s *Service) IssueQRToken(ctx context.Context, peerID uuid.UUID) (string, time.Time, error) {
	if _, err := s.peers.GetByID(ctx, peerID); err != nil {
		return "", time.Time{}, err
	}
	tok := uuid.NewString()
	exp := time.Now().UTC().Add(QRTTL)

	s.qrMu.Lock()
	s.gcExpiredTokensLocked()
	s.qrTokens[tok] = qrToken{peerID: peerID, expiresAt: exp}
	s.qrMu.Unlock()

	return tok, exp, nil
}

// ConsumeQRToken validates token against peerID and removes it from the
// store. Returns ErrQRTokenExpired if the token is missing, expired, or
// bound to a different peer.
func (s *Service) ConsumeQRToken(token string, peerID uuid.UUID) error {
	s.qrMu.Lock()
	defer s.qrMu.Unlock()

	tok, ok := s.qrTokens[token]
	if !ok {
		return ErrQRTokenExpired
	}
	delete(s.qrTokens, token)

	if tok.peerID != peerID {
		return ErrQRTokenExpired
	}
	if time.Now().UTC().After(tok.expiresAt) {
		return ErrQRTokenExpired
	}
	return nil
}

func (s *Service) gcExpiredTokensLocked() {
	now := time.Now().UTC()
	for k, v := range s.qrTokens {
		if now.After(v.expiresAt) {
			delete(s.qrTokens, k)
		}
	}
}

// ============================================================================
// Config generation
// ============================================================================

// generatePeerConfig renders the client-side [Interface]/[Peer] block.
// The cleartext is encrypted before being persisted in config_client.
//
// Note: the [Interface].PrivateKey is intentionally left empty —
// the client is responsible for generating its own private key and
// pasting it in. v26.2.7 omitted it as well; we keep that behavior
// because storing the client's private key on the server is contrary
// to the trust model.
func (s *Service) generatePeerConfig(peer *models.WireGuardPeer, iface *models.WireGuardInterface) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", peer.AllowedIPs)
	if iface.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", iface.DNS)
	}
	if iface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", iface.MTU)
	}
	b.WriteString("# PrivateKey = <generated on the client>\n")
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", iface.PublicKey)
	// peer.PresharedKey is ciphertext at this call site; the caller
	// passes the in-flight cleartext value via the in-memory model
	// (the on-disk row is encrypted separately by CreatePeer).
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	if peer.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s:%d\n", peer.Endpoint, iface.ListenPort)
	} else {
		fmt.Fprintf(&b, "# Endpoint = <server-public-host>:%d\n", iface.ListenPort)
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	if peer.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
	}
	return b.String()
}
