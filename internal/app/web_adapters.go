// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	redisrepo "github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/web"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/profile"
)

// ============================================================================
// H1: UserRepository adapter (postgres.UserRepository → web.UserRepository)
// ============================================================================

type webUserRepoAdapter struct {
	repo *postgres.UserRepository
}

func (a *webUserRepoAdapter) GetUserByID(id string) (*web.UserInfo, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return nil, err
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	return &web.UserInfo{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    email,
		Role:     string(user.Role),
		IsActive: user.IsActive,
	}, nil
}

func (a *webUserRepoAdapter) UpdateUser(id string, username string, email string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return err
	}
	user.Username = username
	if email != "" {
		user.Email = &email
	} else {
		user.Email = nil
	}
	return a.repo.Update(context.Background(), user)
}

func (a *webUserRepoAdapter) UpdatePassword(id string, currentHash string, newHash string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.UpdatePassword(context.Background(), uid, newHash)
}

func (a *webUserRepoAdapter) GetPasswordHash(id string) (string, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return "", err
	}
	return user.PasswordHash, nil
}

func (a *webUserRepoAdapter) DeleteUser(id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Delete(context.Background(), uid)
}

// ============================================================================
// H2: SessionRepository adapter (redis.SessionStore → web.SessionRepository)
// ============================================================================

type webSessionRepoAdapter struct {
	redisStore *redisrepo.SessionStore
}

func (a *webSessionRepoAdapter) GetUserSessions(userID string) ([]profile.SessionInfo, error) {
	sessions, err := a.redisStore.GetAllForUser(context.Background(), userID)
	if err != nil {
		return nil, err
	}
	var infos []profile.SessionInfo
	for _, s := range sessions {
		infos = append(infos, profile.SessionInfo{
			ID:        s.ID,
			IP:        s.IPAddress,
			UserAgent: s.UserAgent,
			Created:   s.CreatedAt.Format("2006-01-02 15:04"),
			LastUsed:  s.LastAccessAt.Format("2006-01-02 15:04"),
		})
	}
	return infos, nil
}

func (a *webSessionRepoAdapter) DeleteSession(sessionID string) error {
	return a.redisStore.Delete(context.Background(), sessionID)
}

func (a *webSessionRepoAdapter) DeleteAllSessionsExcept(userID string, currentSessionID string) error {
	return a.redisStore.DeleteAllForUserExcept(context.Background(), userID, currentSessionID)
}

func (a *webSessionRepoAdapter) GetCurrentSessionID(r *http.Request) string {
	cookie, err := r.Cookie("usulnet_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ============================================================================
// H3: TerminalSessionRepository adapter
// (postgres.TerminalSessionRepository → web.TerminalSessionRepository)
// ============================================================================

type webTerminalSessionRepoAdapter struct {
	repo *postgres.TerminalSessionRepository
}

func (a *webTerminalSessionRepoAdapter) Create(ctx context.Context, input *web.CreateTerminalSessionInput) (uuid.UUID, error) {
	pgInput := &postgres.CreateTerminalSessionInput{
		UserID:     input.UserID,
		Username:   input.Username,
		TargetType: input.TargetType,
		TargetID:   input.TargetID,
		TargetName: input.TargetName,
		HostID:     input.HostID,
		Shell:      input.Shell,
		TermCols:   input.TermCols,
		TermRows:   input.TermRows,
		ClientIP:   input.ClientIP,
		UserAgent:  input.UserAgent,
	}
	return a.repo.Create(ctx, pgInput)
}

func (a *webTerminalSessionRepoAdapter) End(ctx context.Context, sessionID uuid.UUID, status, errorMsg string) error {
	return a.repo.End(ctx, sessionID, status, errorMsg)
}

func (a *webTerminalSessionRepoAdapter) UpdateResize(ctx context.Context, sessionID uuid.UUID, cols, rows int) error {
	return a.repo.UpdateResize(ctx, sessionID, cols, rows)
}

func (a *webTerminalSessionRepoAdapter) Get(ctx context.Context, sessionID uuid.UUID) (*web.TerminalSession, error) {
	pgSession, err := a.repo.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return convertTerminalSession(pgSession), nil
}

func (a *webTerminalSessionRepoAdapter) List(ctx context.Context, opts web.TerminalSessionListOptions) ([]*web.TerminalSession, int, error) {
	pgOpts := postgres.ListTerminalSessionOptions{
		UserID:     opts.UserID,
		TargetType: opts.TargetType,
		TargetID:   opts.TargetID,
		HostID:     opts.HostID,
		Status:     opts.Status,
		Since:      opts.Since,
		Until:      opts.Until,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}
	pgSessions, total, err := a.repo.List(ctx, pgOpts)
	if err != nil {
		return nil, 0, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, total, nil
}

func (a *webTerminalSessionRepoAdapter) GetByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetByTarget(ctx, targetType, targetID, limit)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func (a *webTerminalSessionRepoAdapter) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetByUser(ctx, userID, limit)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func (a *webTerminalSessionRepoAdapter) GetActiveSessions(ctx context.Context) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetActiveSessions(ctx)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func convertTerminalSession(pg *postgres.TerminalSession) *web.TerminalSession {
	return &web.TerminalSession{
		ID:           pg.ID,
		UserID:       pg.UserID,
		Username:     pg.Username,
		TargetType:   pg.TargetType,
		TargetID:     pg.TargetID,
		TargetName:   pg.TargetName,
		HostID:       pg.HostID,
		Shell:        pg.Shell,
		TermCols:     pg.TermCols,
		TermRows:     pg.TermRows,
		ClientIP:     pg.ClientIP,
		StartedAt:    pg.StartedAt,
		EndedAt:      pg.EndedAt,
		DurationMs:   pg.DurationMs,
		Status:       pg.Status,
		ErrorMessage: pg.ErrorMessage,
	}
}
