// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"

	"github.com/google/uuid"
)

// auditBuilder is a tiny fluent builder for AuditEntry rows. It keeps
// the Service methods readable: every audit append is one chained
// statement instead of a five-line struct literal.
type auditBuilder struct {
	entry AuditEntry
}

// newAuditEntry starts a builder for the given canonical action string.
// The action SHOULD be one of the AuditAction* constants in recon.go;
// anything else lands in the recon_audit_log as-is and shows up in
// reports.
func newAuditEntry(action string) *auditBuilder {
	return &auditBuilder{entry: AuditEntry{Action: action}}
}

func (b *auditBuilder) Actor(id *uuid.UUID) *auditBuilder {
	b.entry.ActorID = id
	return b
}

func (b *auditBuilder) Target(id uuid.UUID) *auditBuilder {
	b.entry.TargetID = &id
	return b
}

func (b *auditBuilder) Scan(id uuid.UUID) *auditBuilder {
	b.entry.ScanID = &id
	return b
}

func (b *auditBuilder) IP(ip string) *auditBuilder {
	b.entry.IP = ip
	return b
}

// WithDetail attaches one key/value to Details, lazily allocating the
// map. The Service NEVER passes raw target values here — see the PII
// rule in docs/recon.md §11. Use HexPrefix(value_hash, …) when a
// correlator is needed.
func (b *auditBuilder) WithDetail(key string, value any) *auditBuilder {
	if b.entry.Details == nil {
		b.entry.Details = make(map[string]any, 4)
	}
	b.entry.Details[key] = value
	return b
}

func (b *auditBuilder) Build() AuditEntry { return b.entry }

// appendAudit forwards the entry to the repository's append-only audit
// sink. Audit append failure is never fatal — the Service logs it and
// continues — so the caller does not need to thread the error.
func (s *Implementation) appendAudit(ctx context.Context, entry AuditEntry) {
	if s.repo == nil {
		return
	}
	if err := s.repo.AppendAudit(ctx, entry); err != nil {
		s.log.Warn("audit append failed",
			"action", entry.Action,
			"target_id", entry.TargetID,
			"scan_id", entry.ScanID,
			"error", err,
		)
	}
}
