// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

// Session represents a user session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	UserAgent    string    `json:"user_agent,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessAt time.Time `json:"last_access_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Data         map[string]interface{} `json:"data,omitempty"`
}

// SessionStore handles session operations
type SessionStore struct {
	client *Client
	prefix string
	ttl    time.Duration
}

// NewSessionStore creates a new session store
func NewSessionStore(client *Client, ttl time.Duration) *SessionStore {
	return &SessionStore{
		client: client,
		prefix: "session:",
		ttl:    ttl,
	}
}

// sessionKey generates the Redis key for a session
func (s *SessionStore) sessionKey(sessionID string) string {
	return s.prefix + sessionID
}

// userSessionsKey generates the Redis key for user's session set
func (s *SessionStore) userSessionsKey(userID string) string {
	return s.prefix + "user:" + userID
}

// Create creates a new session
func (s *SessionStore) Create(ctx context.Context, userID, username, role, userAgent, ipAddress string) (*Session, error) {
	now := time.Now()
	session := &Session{
		ID:           uuid.New().String(),
		UserID:       userID,
		Username:     username,
		Role:         role,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		CreatedAt:    now,
		LastAccessAt: now,
		ExpiresAt:    now.Add(s.ttl),
		Data:         make(map[string]interface{}),
	}

	data, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session: %w", err)
	}

	pipe := s.client.rdb.Pipeline()

	// Store session
	pipe.Set(ctx, s.sessionKey(session.ID), data, s.ttl)

	// Add to user's session set
	pipe.SAdd(ctx, s.userSessionsKey(userID), session.ID)
	pipe.Expire(ctx, s.userSessionsKey(userID), s.ttl*2) // Keep user set alive a bit longer

	_, err = pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// Get retrieves a session by ID
func (s *SessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	data, err := s.client.rdb.Get(ctx, s.sessionKey(sessionID)).Bytes()
	if err != nil {
		if err == goredis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		_ = s.Delete(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// Touch updates the last access time and extends TTL
func (s *SessionStore) Touch(ctx context.Context, sessionID string) error {
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	session.LastAccessAt = time.Now()
	session.ExpiresAt = time.Now().Add(s.ttl)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	return s.client.rdb.Set(ctx, s.sessionKey(sessionID), data, s.ttl).Err()
}

// Update updates session data
func (s *SessionStore) Update(ctx context.Context, sessionID string, updateFn func(*Session)) error {
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	updateFn(session)
	session.LastAccessAt = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Calculate remaining TTL
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = s.ttl
		session.ExpiresAt = time.Now().Add(s.ttl)
	}

	return s.client.rdb.Set(ctx, s.sessionKey(sessionID), data, ttl).Err()
}

// SetData sets a value in session data
func (s *SessionStore) SetData(ctx context.Context, sessionID, key string, value interface{}) error {
	return s.Update(ctx, sessionID, func(session *Session) {
		if session.Data == nil {
			session.Data = make(map[string]interface{})
		}
		session.Data[key] = value
	})
}

// GetData gets a value from session data
func (s *SessionStore) GetData(ctx context.Context, sessionID, key string) (interface{}, error) {
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Data == nil {
		return nil, nil
	}

	return session.Data[key], nil
}

// Delete removes a session
func (s *SessionStore) Delete(ctx context.Context, sessionID string) error {
	// Get session first to know the user ID
	session, err := s.Get(ctx, sessionID)
	if err != nil && err != ErrSessionNotFound && err != ErrSessionExpired {
		return err
	}

	pipe := s.client.rdb.Pipeline()

	// Delete session
	pipe.Del(ctx, s.sessionKey(sessionID))

	// Remove from user's session set if we found the session
	if session != nil {
		pipe.SRem(ctx, s.userSessionsKey(session.UserID), sessionID)
	}

	_, err = pipe.Exec(ctx)
	return err
}

// DeleteAllForUser removes all sessions for a user
func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID string) error {
	// Get all session IDs for user
	sessionIDs, err := s.client.rdb.SMembers(ctx, s.userSessionsKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	// Build keys to delete
	keys := make([]string, 0, len(sessionIDs)+1)
	for _, sid := range sessionIDs {
		keys = append(keys, s.sessionKey(sid))
	}
	keys = append(keys, s.userSessionsKey(userID))

	return s.client.rdb.Del(ctx, keys...).Err()
}

// DeleteAllForUserExcept removes all sessions for a user except the specified one
func (s *SessionStore) DeleteAllForUserExcept(ctx context.Context, userID, exceptSessionID string) error {
	sessionIDs, err := s.client.rdb.SMembers(ctx, s.userSessionsKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	pipe := s.client.rdb.Pipeline()
	for _, sid := range sessionIDs {
		if sid != exceptSessionID {
			pipe.Del(ctx, s.sessionKey(sid))
			pipe.SRem(ctx, s.userSessionsKey(userID), sid)
		}
	}

	_, err = pipe.Exec(ctx)
	return err
}

// GetAllForUser returns all sessions for a user
func (s *SessionStore) GetAllForUser(ctx context.Context, userID string) ([]*Session, error) {
	sessionIDs, err := s.client.rdb.SMembers(ctx, s.userSessionsKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return []*Session{}, nil
	}

	// Get all sessions
	keys := make([]string, len(sessionIDs))
	for i, sid := range sessionIDs {
		keys[i] = s.sessionKey(sid)
	}

	results, err := s.client.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(results))
	expiredIDs := make([]string, 0)

	for i, result := range results {
		if result == nil {
			continue
		}

		data, ok := result.(string)
		if !ok {
			continue
		}

		var session Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			continue
		}

		// Check if expired
		if time.Now().After(session.ExpiresAt) {
			expiredIDs = append(expiredIDs, sessionIDs[i])
			continue
		}

		sessions = append(sessions, &session)
	}

	// Clean up expired sessions asynchronously
	if len(expiredIDs) > 0 {
		go func() {
			ctx := context.Background()
			for _, id := range expiredIDs {
				_ = s.Delete(ctx, id)
			}
		}()
	}

	return sessions, nil
}

// CountForUser returns the number of active sessions for a user
func (s *SessionStore) CountForUser(ctx context.Context, userID string) (int64, error) {
	return s.client.rdb.SCard(ctx, s.userSessionsKey(userID)).Result()
}

// Exists checks if a session exists and is valid
func (s *SessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	exists, err := s.client.rdb.Exists(ctx, s.sessionKey(sessionID)).Result()
	if err != nil {
		return false, err
	}

	if exists == 0 {
		return false, nil
	}

	// Verify it's not expired
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return false, nil
	}

	return !time.Now().After(session.ExpiresAt), nil
}

// Errors
var (
	ErrSessionNotFound = fmt.Errorf("session not found")
	ErrSessionExpired  = fmt.Errorf("session expired")
)
