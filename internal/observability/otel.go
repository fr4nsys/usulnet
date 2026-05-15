// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package observability provides OpenTelemetry tracing and metrics middleware
// for the usulnet HTTP server. It integrates with chi/v5 to automatically
// instrument routes with distributed tracing spans and HTTP server metrics.
//
// When disabled (Config.Enabled = false), all middleware functions return
// pass-through handlers with zero overhead.
package observability

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// ============================================================================
// Configuration
// ============================================================================

// Config holds configuration for the OpenTelemetry instrumentation provider.
type Config struct {
	// Enabled controls whether instrumentation is active. When false, all
	// middleware functions return no-op pass-through handlers.
	Enabled bool

	// ServiceName is the logical name of the service reported in traces
	// and metrics (e.g. "usulnet").
	ServiceName string

	// ServiceVersion is the version string reported in the service resource.
	ServiceVersion string

	// Endpoint is the OTLP HTTP collector endpoint (e.g. "localhost:4318").
	// The exporter uses the /v1/traces path automatically.
	Endpoint string

	// Insecure disables TLS for the OTLP exporter connection.
	Insecure bool

	// SampleRatio controls the fraction of traces that are sampled.
	// 1.0 means sample everything, 0.0 means sample nothing.
	// Values outside [0, 1] are clamped by the SDK.
	SampleRatio float64
}

// DefaultConfig returns a Config with sensible defaults.
// Instrumentation is disabled by default to avoid unexpected overhead.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		ServiceName:    "usulnet",
		ServiceVersion: "0.0.0",
		Endpoint:       "localhost:4318",
		Insecure:       true,
		SampleRatio:    1.0,
	}
}

// ============================================================================
// Provider
// ============================================================================

// Provider manages the OpenTelemetry trace and meter providers and exposes
// middleware constructors for chi/v5 routers.
type Provider struct {
	config         Config
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer
	meter          metric.Meter
	propagator     propagation.TextMapPropagator

	// Pre-created metric instruments (initialized once, reused per request).
	requestDuration  metric.Float64Histogram
	activeRequests   metric.Int64UpDownCounter
	requestBodySize  metric.Int64Histogram
	responseBodySize metric.Int64Histogram
}

// NewProvider initializes the OpenTelemetry SDK with an OTLP/HTTP trace
// exporter and returns a ready-to-use Provider. If cfg.Enabled is false the
// returned Provider is valid but all middleware functions are no-ops.
//
// The caller must invoke Provider.Shutdown before the process exits to flush
// any pending telemetry data.
func NewProvider(cfg Config) (*Provider, error) {
	p := &Provider{
		config:     cfg,
		propagator: propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	}

	if !cfg.Enabled {
		// Use global no-op providers so helper functions still work without
		// nil-checks everywhere.
		p.tracer = otel.Tracer(cfg.ServiceName)
		p.meter = otel.Meter(cfg.ServiceName)
		return p, nil
	}

	// Build the OTLP/HTTP exporter.
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("observability: create OTLP exporter: %w", err)
	}

	// Build the service resource.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("observability: create resource: %w", err)
	}

	// Build the tracer provider.
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Register globally so libraries that use otel.GetTracerProvider() pick it up.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(p.propagator)

	p.tracerProvider = tp
	p.tracer = tp.Tracer(cfg.ServiceName)
	p.meter = otel.Meter(cfg.ServiceName)

	// Create metric instruments.
	if err := p.initMetrics(); err != nil {
		// Non-fatal: tracing still works. Metrics will be no-ops.
		_ = err
	}

	return p, nil
}

// initMetrics creates the OTel metric instruments used by the metrics middleware.
func (p *Provider) initMetrics() error {
	var err error

	p.requestDuration, err = p.meter.Float64Histogram(
		"http_server_request_duration_seconds",
		metric.WithDescription("Duration of HTTP server requests in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("create request duration histogram: %w", err)
	}

	p.activeRequests, err = p.meter.Int64UpDownCounter(
		"http_server_active_requests",
		metric.WithDescription("Number of in-flight HTTP server requests"),
	)
	if err != nil {
		return fmt.Errorf("create active requests counter: %w", err)
	}

	p.requestBodySize, err = p.meter.Int64Histogram(
		"http_server_request_body_size_bytes",
		metric.WithDescription("Size of HTTP server request bodies in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return fmt.Errorf("create request body size histogram: %w", err)
	}

	p.responseBodySize, err = p.meter.Int64Histogram(
		"http_server_response_body_size_bytes",
		metric.WithDescription("Size of HTTP server response bodies in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return fmt.Errorf("create response body size histogram: %w", err)
	}

	return nil
}

// Shutdown flushes pending telemetry data and releases resources.
// It should be called with a context that has a reasonable deadline
// (e.g. 5 seconds) during application shutdown.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tracerProvider == nil {
		return nil
	}
	return p.tracerProvider.Shutdown(ctx)
}

// Tracer returns the underlying OTel tracer for manual span creation.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Meter returns the underlying OTel meter for custom metric instruments.
func (p *Provider) Meter() metric.Meter {
	return p.meter
}

// ============================================================================
// Trace Middleware
// ============================================================================

// TraceMiddleware returns a chi-compatible middleware that creates a tracing
// span for every HTTP request. The span name is derived from the chi route
// pattern (e.g. "GET /containers/{id}") when available.
//
// Span attributes follow OpenTelemetry semantic conventions for HTTP:
//   - http.method
//   - http.route
//   - http.status_code
//   - http.url
//   - http.scheme
//   - http.user_agent
//   - net.host.name
//   - net.host.port
//
// When the Provider is disabled, the returned middleware is a no-op.
func (p *Provider) TraceMiddleware() func(http.Handler) http.Handler {
	if !p.config.Enabled {
		return noopMiddleware
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract any incoming trace context from request headers.
			ctx := p.propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Derive the span name from the chi route pattern. Because chi
			// resolves the pattern after routing, we start with a generic
			// name and update it in a deferred call once the route context
			// is populated.
			spanName := r.Method + " " + r.URL.Path

			ctx, span := p.tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPMethod(r.Method),
					semconv.HTTPURL(r.URL.String()),
					semconv.HTTPScheme(httpScheme(r)),
					semconv.UserAgentOriginal(r.UserAgent()),
					semconv.NetHostName(hostFromRequest(r)),
				),
			)
			defer span.End()

			// Inject the trace context into response headers so downstream
			// services can correlate.
			p.propagator.Inject(ctx, propagation.HeaderCarrier(w.Header()))

			// Wrap the response writer to capture the status code.
			rw := newResponseWriter(w)

			// Serve the request with the trace context.
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Now that chi has resolved the route, update the span name
			// and add the route pattern attribute.
			routePattern := chiRoutePattern(r)
			if routePattern != "" {
				span.SetName(r.Method + " " + routePattern)
				span.SetAttributes(semconv.HTTPRoute(routePattern))
			}

			// Record the status code.
			span.SetAttributes(semconv.HTTPStatusCode(rw.status))

			// Mark the span as error for 5xx responses.
			if rw.status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, http.StatusText(rw.status))
			}
		})
	}
}

// ============================================================================
// Metrics Middleware
// ============================================================================

// MetricsMiddleware returns a chi-compatible middleware that records HTTP
// server metrics for every request:
//
//   - http_server_request_duration_seconds  (histogram)
//   - http_server_active_requests           (up-down counter)
//   - http_server_request_body_size_bytes   (histogram)
//   - http_server_response_body_size_bytes  (histogram)
//
// Metric attributes: http.method, http.route, http.status_code.
//
// When the Provider is disabled, the returned middleware is a no-op.
func (p *Provider) MetricsMiddleware() func(http.Handler) http.Handler {
	if !p.config.Enabled {
		return noopMiddleware
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Track in-flight requests.
			commonAttrs := metric.WithAttributes(
				attribute.String("http.method", r.Method),
			)
			if p.activeRequests != nil {
				p.activeRequests.Add(r.Context(), 1, commonAttrs)
			}

			// Record request body size if known.
			if r.ContentLength > 0 && p.requestBodySize != nil {
				p.requestBodySize.Record(r.Context(), r.ContentLength, commonAttrs)
			}

			// Wrap writer to capture status and response size.
			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)

			// Compute route-enriched attributes after chi has resolved the pattern.
			routePattern := chiRoutePattern(r)
			if routePattern == "" {
				routePattern = "unknown"
			}

			attrs := metric.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.route", routePattern),
				attribute.Int("http.status_code", rw.status),
			)

			// Record duration.
			elapsed := time.Since(start).Seconds()
			if p.requestDuration != nil {
				p.requestDuration.Record(r.Context(), elapsed, attrs)
			}

			// Record response body size.
			if p.responseBodySize != nil {
				p.responseBodySize.Record(r.Context(), int64(rw.size), attrs)
			}

			// Decrement in-flight counter.
			if p.activeRequests != nil {
				p.activeRequests.Add(r.Context(), -1, commonAttrs)
			}
		})
	}
}

// ============================================================================
// Span Context Helpers
// ============================================================================

// SpanFromContext returns the current span from a context. This is a thin
// convenience wrapper around trace.SpanFromContext.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDFromContext extracts the trace ID string from the current span
// context. Returns an empty string if the context carries no span or the
// trace ID is invalid.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts the span ID string from the current span
// context. Returns an empty string if the context carries no span or the
// span ID is invalid.
func SpanIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if sc.HasSpanID() {
		return sc.SpanID().String()
	}
	return ""
}

// AddSpanAttributes adds key-value attributes to the span in the given
// context. If no span is active, this is a no-op.
func AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// AddSpanEvent records a named event on the span in the given context.
// If no span is active, this is a no-op.
func AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// RecordError records an error on the span in the given context and sets the
// span status to Error. If err is nil or no span is active, this is a no-op.
func RecordError(ctx context.Context, err error, attrs ...attribute.KeyValue) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err, trace.WithAttributes(attrs...))
		span.SetStatus(codes.Error, err.Error())
	}
}

// StartSpan starts a new child span with the given name and returns the
// updated context and span. The caller must call span.End() when done.
//
//	ctx, span := observability.StartSpan(ctx, "myOperation")
//	defer span.End()
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer("").Start(ctx, name, opts...)
}

// ============================================================================
// Internal helpers
// ============================================================================

// noopMiddleware is a pass-through middleware with zero overhead.
func noopMiddleware(next http.Handler) http.Handler {
	return next
}

// chiRoutePattern extracts the resolved route pattern from the chi route
// context. This must be called AFTER the downstream handler has executed
// so that chi has had the chance to populate the route context.
func chiRoutePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return ""
	}
	return rctx.RoutePattern()
}

// httpScheme returns "https" or "http" based on the request TLS state and
// common proxy headers.
func httpScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// hostFromRequest extracts the hostname (without port) from the request.
func hostFromRequest(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// ============================================================================
// Response writer wrapper
// ============================================================================

// responseWriter wraps http.ResponseWriter to capture the status code and
// response body size. It implements http.Hijacker and http.Flusher so that
// WebSocket upgrades and SSE streaming continue to work.
type responseWriter struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Unwrap returns the underlying ResponseWriter for compatibility with
// http.ResponseController and other interface assertions.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack implements http.Hijacker. Required for WebSocket upgrades.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher. Required for SSE and streaming responses.
func (rw *responseWriter) Flush() {
	if fl, ok := rw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
