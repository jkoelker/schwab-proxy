package metrics

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// meterKey is the context key for storing the meter.
	meterKey contextKey = "meter"

	// attributePairSize is used to calculate the slice capacity for key-value pairs.
	attributePairSize = 2
)

var (
	// defaultMeter is the fallback meter when none is found in context.
	defaultMeter metric.Meter //nolint:gochecknoglobals // Thread-safe: protected by sync.Once

	// meterOnce ensures we only initialize the default meter once.
	meterOnce sync.Once //nolint:gochecknoglobals // Thread-safe: sync.Once is inherently safe
)

// InitializeMeter sets up the global default meter.
func InitializeMeter(serviceName string) {
	meterOnce.Do(func() {
		defaultMeter = otel.Meter(serviceName)
	})
}

// WithMeter adds a meter to the context.
func WithMeter(ctx context.Context, meter metric.Meter) context.Context {
	return context.WithValue(ctx, meterKey, meter)
}

// FromContext retrieves the meter from context or returns the default.
func FromContext(ctx context.Context) metric.Meter {
	if ctxMeter, ok := ctx.Value(meterKey).(metric.Meter); ok {
		return ctxMeter
	}

	return defaultMeter
}

// Counter creates or retrieves a counter instrument.
type Counter struct {
	instrument metric.Int64Counter
}

// CounterFromContext creates a new counter from the context.
func CounterFromContext(
	ctx context.Context,
	name string,
	opts ...metric.Int64CounterOption,
) *Counter {
	meter := FromContext(ctx)

	instrument, err := meter.Int64Counter(name, opts...)
	if err != nil {
		// In production, you might want to log this error
		// For now, return a no-op counter
		return &Counter{instrument: nil}
	}

	return &Counter{instrument: instrument}
}

// Add records a counter increment with optional attributes.
func (c *Counter) Add(ctx context.Context, incr int64, attrs ...string) {
	if c.instrument == nil {
		return
	}

	attributes := convertStringPairsToAttributes(attrs...)
	c.instrument.Add(ctx, incr, metric.WithAttributes(attributes...))
}

// Histogram creates or retrieves a histogram instrument.
type Histogram struct {
	instrument metric.Float64Histogram
}

// HistogramFromContext creates a new histogram from the context.
func HistogramFromContext(
	ctx context.Context,
	name string,
	opts ...metric.Float64HistogramOption,
) *Histogram {
	meter := FromContext(ctx)

	instrument, err := meter.Float64Histogram(name, opts...)
	if err != nil {
		// In production, you might want to log this error
		// For now, return a no-op histogram
		return &Histogram{instrument: nil}
	}

	return &Histogram{instrument: instrument}
}

// Record records a histogram value with optional attributes.
func (h *Histogram) Record(ctx context.Context, value float64, attrs ...string) {
	if h.instrument == nil {
		return
	}

	attributes := convertStringPairsToAttributes(attrs...)
	h.instrument.Record(ctx, value, metric.WithAttributes(attributes...))
}

// Gauge creates or retrieves a gauge instrument (using UpDownCounter).
type Gauge struct {
	instrument metric.Int64UpDownCounter
}

// GaugeFromContext creates a new gauge from the context.
func GaugeFromContext(
	ctx context.Context,
	name string,
	opts ...metric.Int64UpDownCounterOption,
) *Gauge {
	meter := FromContext(ctx)

	instrument, err := meter.Int64UpDownCounter(name, opts...)
	if err != nil {
		// In production, you might want to log this error
		// For now, return a no-op gauge
		return &Gauge{instrument: nil}
	}

	return &Gauge{instrument: instrument}
}

// Set sets the gauge to a specific value (using Add with delta).
func (g *Gauge) Set(ctx context.Context, value int64, attrs ...string) {
	if g.instrument == nil {
		return
	}

	attributes := convertStringPairsToAttributes(attrs...)
	g.instrument.Add(ctx, value, metric.WithAttributes(attributes...))
}

// Add adds to the gauge value.
func (g *Gauge) Add(ctx context.Context, delta int64, attrs ...string) {
	if g.instrument == nil {
		return
	}

	attributes := convertStringPairsToAttributes(attrs...)
	g.instrument.Add(ctx, delta, metric.WithAttributes(attributes...))
}

// Convenience functions that mirror the log package pattern

// GetCounter returns a counter instrument from context.
func GetCounter(ctx context.Context, name string, opts ...metric.Int64CounterOption) *Counter {
	return CounterFromContext(ctx, name, opts...)
}

// GetHistogram returns a histogram instrument from context.
func GetHistogram(
	ctx context.Context,
	name string,
	opts ...metric.Float64HistogramOption,
) *Histogram {
	return HistogramFromContext(ctx, name, opts...)
}

// GetGauge returns a gauge instrument from context.
func GetGauge(ctx context.Context, name string, opts ...metric.Int64UpDownCounterOption) *Gauge {
	return GaugeFromContext(ctx, name, opts...)
}

// RecordCounter is a convenience function to record a counter increment.
func RecordCounter(ctx context.Context, name string, incr int64, attrs ...string) {
	GetCounter(ctx, name).Add(ctx, incr, attrs...)
}

// RecordHistogram is a convenience function to record a histogram value.
func RecordHistogram(ctx context.Context, name string, value float64, attrs ...string) {
	GetHistogram(ctx, name).Record(ctx, value, attrs...)
}

// RecordGauge is a convenience function to set a gauge value.
func RecordGauge(ctx context.Context, name string, value int64, attrs ...string) {
	GetGauge(ctx, name).Set(ctx, value, attrs...)
}

// convertStringPairsToAttributes converts key-value string pairs to OTel attributes
// This mirrors the pattern used in the log package.
func convertStringPairsToAttributes(keyValues ...string) []attribute.KeyValue {
	if len(keyValues)%attributePairSize != 0 {
		// If odd number of arguments, ignore the last one
		keyValues = keyValues[:len(keyValues)-1]
	}

	attrs := make([]attribute.KeyValue, 0, len(keyValues)/attributePairSize)

	for i := 0; i < len(keyValues); i += attributePairSize {
		key := keyValues[i]
		value := keyValues[i+1]
		attrs = append(attrs, attribute.String(key, value))
	}

	return attrs
}
