package tracing_test

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/jkoelker/schwab-proxy/tracing"
)

func TestInitializeTracer(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")
}

func TestWithTracer(t *testing.T) {
	t.Parallel()

	testTracer := noop.NewTracerProvider().Tracer("test")
	ctx := t.Context()

	ctx = tracing.WithTracer(ctx, testTracer)

	retrievedTracer := tracing.FromContext(ctx)
	if retrievedTracer != testTracer {
		t.Error("Expected to retrieve the same tracer from context")
	}
}

func TestFromContextFallback(t *testing.T) {
	t.Parallel()

	// Initialize default tracer first
	tracing.InitializeTracer("test-service")

	ctx := t.Context()
	tracer := tracing.FromContext(ctx)

	// We can't compare with defaultTracer since it's not exported
	// But we should get a valid tracer
	if tracer == nil {
		t.Error("Expected to get a valid tracer")
	}
}

func TestStartSpan(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	ctx, span := tracing.StartSpan(ctx, "test-span")
	defer span.End()

	if span == nil {
		t.Error("Expected span to be created")
	}

	// Verify span is in context - we can't compare spans directly, so just check if it's not nil
	retrievedSpan := tracing.SpanFromContext(ctx)
	if retrievedSpan == nil {
		t.Error("Expected to retrieve a span from context")
	}
}

func TestSpanOperations(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	ctx, span := tracing.StartSpan(ctx, "test-span")
	defer span.End()

	// Test adding attributes
	tracing.SetAttributes(ctx, "key1", "value1", "key2", "value2")

	// Test adding event
	tracing.AddEvent(ctx, "test-event", "event_key", "event_value")

	// Test setting OK status
	tracing.SetOK(ctx)
}

func TestSetError(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	ctx, span := tracing.StartSpan(ctx, "test-span")
	defer span.End()

	testErr := errors.New("test error")
	tracing.SetError(ctx, testErr)
}

func TestWithAttributes(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	ctx, span := tracing.StartSpan(ctx, "test-span")
	defer span.End()

	// Test WithAttributes convenience function
	_ = tracing.WithAttributes(ctx, "attr1", "value1", "attr2", "value2")
}

func TestWithSpan(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	// Test successful execution
	if err := tracing.WithSpan(ctx, "test-operation", func(ctx context.Context) error {
		// Simulate some work
		tracing.SetAttributes(ctx, "operation", "success")

		return nil
	}); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test error handling
	testErr := errors.New("test error")
	if err := tracing.WithSpan(ctx, "failing-operation", func(_ context.Context) error {
		return testErr
	}); !errors.Is(err, testErr) {
		t.Errorf("Expected test error, got %v", err)
	}
}

func TestWithSpanNoError(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	ctx := t.Context()

	called := false

	tracing.WithSpanNoError(ctx, "test-operation", func(ctx context.Context) {
		called = true

		tracing.SetAttributes(ctx, "operation", "completed")
	})

	if !called {
		t.Error("Expected function to be called")
	}
}

func TestConvertStringPairsToAttributes(t *testing.T) {
	t.Parallel()

	tracing.InitializeTracer("test-service")

	// We can't test convertStringPairsToAttributes directly since it's not exported
	// Instead, we'll test through the public SetAttributes function
	ctx, span := tracing.StartSpan(t.Context(), "test-span")
	defer span.End()

	// These should not panic
	tracing.SetAttributes(ctx, "key1", "value1", "key2", "value2")

	// Test odd number of arguments (should not panic)
	tracing.SetAttributes(ctx, "key1", "value1", "key2")

	// Test empty arguments (should not panic)
	tracing.SetAttributes(ctx)
}
