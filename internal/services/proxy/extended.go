// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// Extended proxy features (v26.5.1 — ported from v26.2.7):
//
//   - Access lists (HTTP basic auth + IP allow/deny)
//   - Dead hosts (404 catch-alls)
//   - Locations (per-host path routes)
//   - Redirections (redirect-only hosts)
//   - Streams (raw TCP/UDP forwarding)
//
// usulnet stores the authoritative state in PostgreSQL. On apply, the
// active backend translates that state to its native API (NPM full,
// Caddy partial — streams unsupported). Streams against Caddy return
// ErrFeatureNotSupported, which API handlers map to HTTP 422.

package proxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ErrFeatureNotSupported is returned by the proxy service when the active
// backend cannot apply a requested feature (e.g. streams against Caddy).
// API handlers translate this to HTTP 422 with a clear message.
var ErrFeatureNotSupported = errors.New("feature not supported by active proxy backend")

// FeatureSupport describes a backend's capability for an extended feature.
type FeatureSupport struct {
	AccessLists  bool
	DeadHosts    bool
	Locations    bool
	Redirections bool
	Streams      bool
}

// SupportMatrix returns the support matrix for the active backend.
//
// Backends implementing ExtendedSyncBackend report their support;
// the legacy SyncBackend default is "no extended features" (Caddy minus
// streams in v26.5.1; nginx supports everything).
func (s *Service) SupportMatrix() FeatureSupport {
	if ext, ok := s.backend.(ExtendedSyncBackend); ok {
		return ext.SupportMatrix()
	}
	// Conservative default: assume no extended-feature backend support
	// until the backend explicitly opts in. This keeps untranslated
	// backends from silently swallowing config changes.
	return FeatureSupport{}
}

// ExtendedSyncData carries the extended-feature state. Backends use it
// alongside SyncData to render their native configuration.
type ExtendedSyncData struct {
	AccessLists  []*models.ProxyAccessList
	DeadHosts    []*models.ProxyDeadHost
	Locations    map[uuid.UUID][]models.ProxyLocation
	Redirections []*models.ProxyRedirection
	Streams      []*models.ProxyStream
}

// ExtendedSyncBackend is an optional interface a SyncBackend can implement
// to declare and apply extended-feature state alongside the base SyncData.
//
// The proxy service performs a type assertion; legacy backends that do
// not implement this interface skip the extended-feature apply step and
// the service reports ErrFeatureNotSupported to API callers attempting
// to use those features.
type ExtendedSyncBackend interface {
	SyncBackend
	// SupportMatrix returns the features this backend can translate.
	SupportMatrix() FeatureSupport
	// SyncExtended applies the extended-feature state. Implementations
	// must be idempotent — calling SyncExtended twice with the same
	// state must not produce any side effects on the backend.
	SyncExtended(ctx context.Context, data *ExtendedSyncData) error
}

// ============================================================================
// Access Lists
// ============================================================================

// ListAccessLists returns all access lists for the default host.
func (s *Service) ListAccessLists(ctx context.Context) ([]*models.ProxyAccessList, error) {
	if s.accessLists == nil {
		return nil, nil
	}
	return s.accessLists.List(ctx, s.cfg.DefaultHostID)
}

// GetAccessList returns one access list by ID, including items and clients.
func (s *Service) GetAccessList(ctx context.Context, id uuid.UUID) (*models.ProxyAccessList, error) {
	if s.accessLists == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.accessLists.GetByID(ctx, id)
}

// CreateAccessList stores a new access list and triggers a sync.
func (s *Service) CreateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().AccessLists {
		return fmt.Errorf("create access list: %w", ErrFeatureNotSupported)
	}
	if al.HostID == uuid.Nil {
		al.HostID = s.cfg.DefaultHostID
	}
	if err := s.accessLists.Create(ctx, al); err != nil {
		return fmt.Errorf("create access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "create", "access_list", al.ID, al.Name, "")
	return s.applyExtended(ctx)
}

// UpdateAccessList replaces an access list's fields plus items/clients.
func (s *Service) UpdateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().AccessLists {
		return fmt.Errorf("update access list: %w", ErrFeatureNotSupported)
	}
	if err := s.accessLists.Update(ctx, al); err != nil {
		return fmt.Errorf("update access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "update", "access_list", al.ID, al.Name, "")
	return s.applyExtended(ctx)
}

// DeleteAccessList removes an access list and triggers a sync.
func (s *Service) DeleteAccessList(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return ErrFeatureNotSupported
	}
	al, err := s.accessLists.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.accessLists.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "delete", "access_list", id, al.Name, "")
	return s.applyExtended(ctx)
}

// ============================================================================
// Dead Hosts
// ============================================================================

// ListDeadHosts returns all dead hosts (404 catch-alls) for the default host.
func (s *Service) ListDeadHosts(ctx context.Context) ([]*models.ProxyDeadHost, error) {
	if s.deadHosts == nil {
		return nil, nil
	}
	return s.deadHosts.List(ctx, s.cfg.DefaultHostID)
}

// GetDeadHost returns one dead host by ID.
func (s *Service) GetDeadHost(ctx context.Context, id uuid.UUID) (*models.ProxyDeadHost, error) {
	if s.deadHosts == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.deadHosts.GetByID(ctx, id)
}

// CreateDeadHost stores a new dead host and triggers a sync.
func (s *Service) CreateDeadHost(ctx context.Context, d *models.ProxyDeadHost, userID *uuid.UUID) error {
	if s.deadHosts == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().DeadHosts {
		return fmt.Errorf("create dead host: %w", ErrFeatureNotSupported)
	}
	if d.HostID == uuid.Nil {
		d.HostID = s.cfg.DefaultHostID
	}
	if err := s.deadHosts.Create(ctx, d); err != nil {
		return fmt.Errorf("create dead host: %w", err)
	}
	s.auditLog(ctx, d.HostID, userID, "create", "dead_host", d.ID, joinDomains(d.Domains), "")
	return s.applyExtended(ctx)
}

// UpdateDeadHost updates an existing dead host and triggers a sync.
func (s *Service) UpdateDeadHost(ctx context.Context, d *models.ProxyDeadHost, userID *uuid.UUID) error {
	if s.deadHosts == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().DeadHosts {
		return fmt.Errorf("update dead host: %w", ErrFeatureNotSupported)
	}
	if err := s.deadHosts.Update(ctx, d); err != nil {
		return fmt.Errorf("update dead host: %w", err)
	}
	s.auditLog(ctx, d.HostID, userID, "update", "dead_host", d.ID, joinDomains(d.Domains), "")
	return s.applyExtended(ctx)
}

// DeleteDeadHost removes a dead host and triggers a sync.
func (s *Service) DeleteDeadHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.deadHosts == nil {
		return ErrFeatureNotSupported
	}
	d, err := s.deadHosts.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.deadHosts.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete dead host: %w", err)
	}
	s.auditLog(ctx, d.HostID, userID, "delete", "dead_host", id, joinDomains(d.Domains), "")
	return s.applyExtended(ctx)
}

// ============================================================================
// Locations
// ============================================================================

// ListLocations returns all locations for a proxy host.
func (s *Service) ListLocations(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyLocation, error) {
	if s.locations == nil {
		return nil, nil
	}
	return s.locations.ListByHost(ctx, proxyHostID)
}

// SetLocations replaces all locations for a proxy host atomically and triggers a sync.
func (s *Service) SetLocations(ctx context.Context, proxyHostID uuid.UUID, locations []models.ProxyLocation, userID *uuid.UUID) error {
	if s.locations == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().Locations {
		return fmt.Errorf("set locations: %w", ErrFeatureNotSupported)
	}
	if err := s.locations.ReplaceForHost(ctx, proxyHostID, locations); err != nil {
		return fmt.Errorf("set locations: %w", err)
	}
	s.auditLog(ctx, s.cfg.DefaultHostID, userID, "update", "locations", proxyHostID, "", fmt.Sprintf("%d locations", len(locations)))
	return s.applyExtended(ctx)
}

// ============================================================================
// Redirections
// ============================================================================

// ListRedirections returns all redirections for the default host.
func (s *Service) ListRedirections(ctx context.Context) ([]*models.ProxyRedirection, error) {
	if s.redirections == nil {
		return nil, nil
	}
	return s.redirections.List(ctx, s.cfg.DefaultHostID)
}

// GetRedirection returns one redirection by ID.
func (s *Service) GetRedirection(ctx context.Context, id uuid.UUID) (*models.ProxyRedirection, error) {
	if s.redirections == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.redirections.GetByID(ctx, id)
}

// CreateRedirection stores a new redirection and triggers a sync.
func (s *Service) CreateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error {
	if s.redirections == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().Redirections {
		return fmt.Errorf("create redirection: %w", ErrFeatureNotSupported)
	}
	if rd.HostID == uuid.Nil {
		rd.HostID = s.cfg.DefaultHostID
	}
	if err := s.redirections.Create(ctx, rd); err != nil {
		return fmt.Errorf("create redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "create", "redirection", rd.ID, joinDomains(rd.Domains), "")
	return s.applyExtended(ctx)
}

// UpdateRedirection updates a redirection and triggers a sync.
func (s *Service) UpdateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error {
	if s.redirections == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().Redirections {
		return fmt.Errorf("update redirection: %w", ErrFeatureNotSupported)
	}
	if err := s.redirections.Update(ctx, rd); err != nil {
		return fmt.Errorf("update redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "update", "redirection", rd.ID, joinDomains(rd.Domains), "")
	return s.applyExtended(ctx)
}

// DeleteRedirection removes a redirection and triggers a sync.
func (s *Service) DeleteRedirection(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.redirections == nil {
		return ErrFeatureNotSupported
	}
	rd, err := s.redirections.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.redirections.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "delete", "redirection", id, joinDomains(rd.Domains), "")
	return s.applyExtended(ctx)
}

// ============================================================================
// Streams (TCP/UDP — nginx only; Caddy returns ErrFeatureNotSupported)
// ============================================================================

// ListStreams returns all streams for the default host.
func (s *Service) ListStreams(ctx context.Context) ([]*models.ProxyStream, error) {
	if s.streams == nil {
		return nil, nil
	}
	return s.streams.List(ctx, s.cfg.DefaultHostID)
}

// GetStream returns one stream by ID.
func (s *Service) GetStream(ctx context.Context, id uuid.UUID) (*models.ProxyStream, error) {
	if s.streams == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.streams.GetByID(ctx, id)
}

// CreateStream stores a new stream and triggers a sync. Returns
// ErrFeatureNotSupported when the active backend cannot translate
// raw TCP/UDP forwarding.
func (s *Service) CreateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error {
	if s.streams == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().Streams {
		return fmt.Errorf("create stream: %w", ErrFeatureNotSupported)
	}
	if st.HostID == uuid.Nil {
		st.HostID = s.cfg.DefaultHostID
	}
	if err := s.streams.Create(ctx, st); err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "create", "stream", st.ID, fmt.Sprintf("%d", st.IncomingPort), "")
	return s.applyExtended(ctx)
}

// UpdateStream updates a stream and triggers a sync.
func (s *Service) UpdateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error {
	if s.streams == nil {
		return ErrFeatureNotSupported
	}
	if !s.SupportMatrix().Streams {
		return fmt.Errorf("update stream: %w", ErrFeatureNotSupported)
	}
	if err := s.streams.Update(ctx, st); err != nil {
		return fmt.Errorf("update stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "update", "stream", st.ID, fmt.Sprintf("%d", st.IncomingPort), "")
	return s.applyExtended(ctx)
}

// DeleteStream removes a stream and triggers a sync.
func (s *Service) DeleteStream(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.streams == nil {
		return ErrFeatureNotSupported
	}
	st, err := s.streams.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.streams.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "delete", "stream", id, fmt.Sprintf("%d", st.IncomingPort), "")
	return s.applyExtended(ctx)
}

// ============================================================================
// Apply (state → backend translation)
// ============================================================================

// loadExtendedData loads all extended state for the default host.
func (s *Service) loadExtendedData(ctx context.Context) (*ExtendedSyncData, error) {
	data := &ExtendedSyncData{
		Locations: make(map[uuid.UUID][]models.ProxyLocation),
	}
	hostID := s.cfg.DefaultHostID

	if s.accessLists != nil {
		lists, err := s.accessLists.List(ctx, hostID)
		if err != nil {
			return nil, fmt.Errorf("load access lists: %w", err)
		}
		data.AccessLists = lists
	}
	if s.deadHosts != nil {
		dead, err := s.deadHosts.List(ctx, hostID)
		if err != nil {
			return nil, fmt.Errorf("load dead hosts: %w", err)
		}
		data.DeadHosts = dead
	}
	if s.redirections != nil {
		redirs, err := s.redirections.List(ctx, hostID)
		if err != nil {
			return nil, fmt.Errorf("load redirections: %w", err)
		}
		data.Redirections = redirs
	}
	if s.streams != nil {
		streams, err := s.streams.List(ctx, hostID)
		if err != nil {
			return nil, fmt.Errorf("load streams: %w", err)
		}
		data.Streams = streams
	}
	if s.locations != nil {
		grouped, err := s.locations.ListAllGrouped(ctx)
		if err != nil {
			return nil, fmt.Errorf("load proxy locations: %w", err)
		}
		for hostID, locs := range grouped {
			if len(locs) > 0 {
				data.Locations[hostID] = locs
			}
		}
	}
	return data, nil
}

// applyExtended pushes the latest base + extended state to the backend.
//
// The apply is idempotent: replaying the same state must not produce
// any side effects on the underlying backend. Backends implementing
// ExtendedSyncBackend.SyncExtended are responsible for honoring that
// contract.
func (s *Service) applyExtended(ctx context.Context) error {
	// Always sync the base data first so that hosts referenced by
	// extended features (locations, dead hosts) are present in the
	// backend before extended state references them.
	if err := s.Sync(ctx); err != nil {
		return err
	}

	ext, ok := s.backend.(ExtendedSyncBackend)
	if !ok {
		s.logger.Debug("Active proxy backend does not implement extended sync; extended state not pushed", "mode", s.backend.Mode())
		return nil
	}

	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	data, err := s.loadExtendedData(ctx)
	if err != nil {
		return err
	}

	if err := ext.SyncExtended(ctx, data); err != nil {
		return fmt.Errorf("extended sync (%s): %w", s.backend.Mode(), err)
	}
	s.logger.Info("Synced extended proxy configuration",
		"backend", s.backend.Mode(),
		"access_lists", len(data.AccessLists),
		"dead_hosts", len(data.DeadHosts),
		"redirections", len(data.Redirections),
		"streams", len(data.Streams),
		"locations_hosts", len(data.Locations),
	)
	return nil
}

// ApplyExtended is the public entry-point for callers that want to
// re-push the extended state without changing it (e.g. drift correction).
// It is safe to call repeatedly.
func (s *Service) ApplyExtended(ctx context.Context) error {
	return s.applyExtended(ctx)
}

func joinDomains(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}
