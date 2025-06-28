package tracing

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// tracerKey is the context key for storing the tracer.
	tracerKey contextKey = "tracer"

	// keyValuePairSize represents the number of elements in a key-value pair.
	keyValuePairSize = 2
)

var (
	// defaultTracer is the fallback tracer when none is found in context.
	defaultTracer trace.Tracer //nolint:gochecknoglobals // Thread-safe: protected by sync.Once

	// tracerOnce ensures we only initialize the default tracer once.
	tracerOnce sync.Once //nolint:gochecknoglobals // Thread-safe: sync.Once is inherently safe
)

// InitializeTracer sets up the global default tracer.
func InitializeTracer(serviceName string) {
	tracerOnce.Do(func() {
		defaultTracer = otel.Tracer(serviceName)
	})
}

// WithTracer adds a tracer to the context.
func WithTracer(ctx context.Context, tracer trace.Tracer) context.Context {
	return context.WithValue(ctx, tracerKey, tracer)
}

// FromContext retrieves the tracer from context or returns the default.
func FromContext(ctx context.Context) trace.Tracer {
	if ctxTracer, ok := ctx.Value(tracerKey).(trace.Tracer); ok {
		return ctxTracer
	}

	return defaultTracer
}

// StartSpan starts a new span with the given name.
func StartSpan(
	ctx context.Context,
	spanName string,
	opts ...trace.SpanStartOption,
) (context.Context, trace.Span) {
	return FromContext(ctx).Start(ctx, spanName, opts...)
}

// SpanFromContext returns the current span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent adds an event to the current span with optional attributes.
func AddEvent(ctx context.Context, name string, attrs ...string) {
	span := SpanFromContext(ctx)
	if span.IsRecording() {
		attributes := convertStringPairsToAttributes(attrs...)
		span.AddEvent(name, trace.WithAttributes(attributes...))
	}
}

// SetAttributes sets attributes on the current span.
func SetAttributes(ctx context.Context, attrs ...string) {
	span := SpanFromContext(ctx)
	if span.IsRecording() {
		attributes := convertStringPairsToAttributes(attrs...)
		span.SetAttributes(attributes...)
	}
}

// SetError records an error on the current span.
func SetError(ctx context.Context, err error) {
	span := SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// SetOK sets the span status to OK.
func SetOK(ctx context.Context) {
	span := SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetStatus(codes.Ok, "")
	}
}

// WithAttributes is a convenience function that returns a context with span attributes set.
func WithAttributes(ctx context.Context, attrs ...string) context.Context {
	SetAttributes(ctx, attrs...)

	return ctx
}

// convertStringPairsToAttributes converts key-value string pairs to OTel attributes
// This mirrors the pattern used in the log and metrics packages.
func convertStringPairsToAttributes(keyValues ...string) []attribute.KeyValue {
	if len(keyValues)%2 != 0 {
		// If odd number of arguments, ignore the last one
		keyValues = keyValues[:len(keyValues)-1]
	}

	attrs := make([]attribute.KeyValue, 0, len(keyValues)/keyValuePairSize)

	for i := 0; i < len(keyValues); i += 2 {
		key := keyValues[i]
		value := keyValues[i+1]
		attrs = append(attrs, attribute.String(key, value))
	}

	return attrs
}

// Helper functions for common span operations

// WithSpan executes a function within a span, automatically ending the span.
func WithSpan(
	ctx context.Context,
	spanName string,
	function func(context.Context) error,
	opts ...trace.SpanStartOption,
) error {
	ctx, span := StartSpan(ctx, spanName, opts...)
	defer span.End()

	err := function(ctx)
	if err != nil {
		SetError(ctx, err)
	} else {
		SetOK(ctx)
	}

	return err
}

// WithSpanNoError executes a function within a span without error handling.
func WithSpanNoError(
	ctx context.Context,
	spanName string,
	function func(context.Context),
	opts ...trace.SpanStartOption,
) {
	ctx, span := StartSpan(ctx, spanName, opts...)
	defer span.End()

	function(ctx)
	SetOK(ctx)
}
