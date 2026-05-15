// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ============================================================================
// Database Tracing
// ============================================================================

// DBSpanOptions configures a database span.
type DBSpanOptions struct {
	// Operation is the database operation type (e.g., "SELECT", "INSERT", "UPDATE", "DELETE").
	Operation string
	// Table is the target database table name.
	Table string
	// Statement is a sanitized version of the SQL statement (no parameter values).
	Statement string
}

// StartDBSpan starts a new child span for a database operation and returns the
// updated context and span. The caller must call span.End() when the query
// completes.
//
// Usage:
//
//	ctx, span := observability.StartDBSpan(ctx, observability.DBSpanOptions{
//	    Operation: "SELECT",
//	    Table:     "containers",
//	})
//	defer span.End()
func StartDBSpan(ctx context.Context, opts DBSpanOptions) (context.Context, trace.Span) {
	spanName := "db"
	if opts.Operation != "" {
		spanName = fmt.Sprintf("db.%s", opts.Operation)
	}
	if opts.Table != "" {
		spanName = fmt.Sprintf("%s %s", spanName, opts.Table)
	}

	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
	}
	if opts.Operation != "" {
		attrs = append(attrs, attribute.String("db.operation", opts.Operation))
	}
	if opts.Table != "" {
		attrs = append(attrs, attribute.String("db.sql.table", opts.Table))
	}
	if opts.Statement != "" {
		attrs = append(attrs, attribute.String("db.statement", opts.Statement))
	}

	return StartSpan(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

// RecordDBError records a database error on the span and sets the span status
// to Error. If err is nil, this is a no-op.
func RecordDBError(ctx context.Context, err error) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// RecordDBRowsAffected records the number of rows affected by a database
// operation on the current span.
func RecordDBRowsAffected(ctx context.Context, rows int64) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attribute.Int64("db.rows_affected", rows))
	}
}
