package metrics_test

import (
	"testing"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/jkoelker/schwab-proxy/metrics"
)

func TestInitializeMeter(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	// We can't directly access defaultMeter since it's now in a different package
	// Instead, test that FromContext returns a non-nil meter
	ctx := t.Context()

	meter := metrics.FromContext(ctx)
	if meter == nil {
		t.Error("Expected meter to be available from context")
	}
}

func TestWithMeter(t *testing.T) {
	t.Parallel()

	testMeter := noop.NewMeterProvider().Meter("test")
	ctx := t.Context()

	ctx = metrics.WithMeter(ctx, testMeter)

	retrievedMeter := metrics.FromContext(ctx)
	if retrievedMeter != testMeter {
		t.Error("Expected to retrieve the same meter from context")
	}
}

func TestFromContextFallback(t *testing.T) {
	t.Parallel()

	// Initialize default meter first
	metrics.InitializeMeter("test-service")

	ctx := t.Context()
	meter := metrics.FromContext(ctx)

	if meter == nil {
		t.Error("Expected to get non-nil meter when none in context")
	}
}

func TestCounterFromContext(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	counter := metrics.CounterFromContext(ctx, "test_counter")
	if counter == nil {
		t.Error("Expected counter to be created")
	}

	// Test adding with attributes
	counter.Add(ctx, 1, "key", "value")
	counter.Add(ctx, 5, "method", "GET", "status", "200")
}

func TestHistogramFromContext(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	histogram := metrics.HistogramFromContext(ctx, "test_histogram")
	if histogram == nil {
		t.Error("Expected histogram to be created")
	}

	// Test recording with attributes
	histogram.Record(ctx, 123.45, "endpoint", "/api/test")
	histogram.Record(ctx, 67.89, "method", "POST", "status", "201")
}

func TestGaugeFromContext(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	gauge := metrics.GaugeFromContext(ctx, "test_gauge")
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}

	// Test setting and adding with attributes
	gauge.Set(ctx, 10, "resource", "cpu")
	gauge.Add(ctx, 5, "resource", "memory")
}

func TestConvenienceFunctions(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	// Test convenience functions
	metrics.RecordCounter(ctx, "convenience_counter", 1, "test", "true")
	metrics.RecordHistogram(ctx, "convenience_histogram", 99.9, "test", "true")
	metrics.RecordGauge(ctx, "convenience_gauge", 42, "test", "true")
}

func TestConvertStringPairsToAttributes(t *testing.T) {
	t.Parallel()

	// We can't test the internal convertStringPairsToAttributes function directly
	// since it's not exported. Instead, test through the public API.
	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	// Test with even number of attributes - this will internally use convertStringPairsToAttributes
	counter := metrics.CounterFromContext(ctx, "test_convert_counter")
	counter.Add(ctx, 1, "key1", "value1", "key2", "value2")

	// Test with odd number of attributes - should work without panic
	counter.Add(ctx, 1, "key1", "value1", "key2")

	// Test with no attributes
	counter.Add(ctx, 1)
}

func TestCounterAPIPattern(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	// Test the API pattern like log.Info(ctx, "message", "key", "value")
	// Should be: GetCounter(ctx, "name").Add(1, "key", "value")
	metrics.GetCounter(ctx, "api_requests_total").Add(ctx, 1, "method", "GET", "endpoint", "/test")

	// Multiple calls should work (instruments are cached by name)
	metrics.GetCounter(ctx, "api_requests_total").Add(ctx, 1, "method", "POST", "endpoint", "/test")
}

func TestHistogramAPIPattern(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	// Test histogram API pattern
	metrics.GetHistogram(ctx, "request_duration_ms").Record(ctx, 125.5, "method", "GET", "endpoint", "/test")
	metrics.GetHistogram(ctx, "request_duration_ms").Record(ctx, 89.2, "method", "POST", "endpoint", "/test")
}

func TestGaugeAPIPattern(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-service")

	ctx := t.Context()

	// Test gauge API pattern
	metrics.GetGauge(ctx, "active_connections").Set(ctx, 10, "type", "websocket")
	metrics.GetGauge(ctx, "active_connections").Add(ctx, 5, "type", "http")
}
