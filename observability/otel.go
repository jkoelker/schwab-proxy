package observability

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/log"
	appmetrics "github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/tracing"
)

// ErrOTelShutdownFailed is returned when OTel shutdown encounters multiple errors.
var ErrOTelShutdownFailed = errors.New("errors during OTel shutdown")

// OTelConfig holds OpenTelemetry configuration.
type OTelConfig struct {
	ServiceName    string
	MetricsEnabled bool
	TracingEnabled bool
}

// OTelProviders holds the initialized OpenTelemetry providers.
type OTelProviders struct {
	MeterProvider  *metric.MeterProvider
	TracerProvider *sdktrace.TracerProvider
	PrometheusHTTP http.Handler
}

// InitializeOTel sets up OpenTelemetry providers based on configuration.
func InitializeOTel(ctx context.Context, cfg *config.Config) (*OTelProviders, error) {
	providers := &OTelProviders{}

	log.Info(ctx, "Initializing OpenTelemetry",
		"service_name", cfg.ServiceName,
		"metrics_enabled", cfg.MetricsEnabled,
		"tracing_enabled", cfg.TracingEnabled,
	)

	// Initialize metrics if enabled
	if cfg.MetricsEnabled {
		meterProvider, prometheusHandler, err := initializeMetrics(ctx, cfg.ServiceName)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize metrics: %w", err)
		}

		providers.MeterProvider = meterProvider
		providers.PrometheusHTTP = prometheusHandler

		// Set global meter provider
		otel.SetMeterProvider(meterProvider)

		// Initialize our metrics package
		appmetrics.InitializeMeter(cfg.ServiceName)

		log.Info(ctx, "Metrics initialized successfully")
	}

	// Initialize tracing if enabled
	if cfg.TracingEnabled {
		tracerProvider := initializeTracing(ctx, cfg.ServiceName)
		providers.TracerProvider = tracerProvider

		// Set global tracer provider
		otel.SetTracerProvider(tracerProvider)

		// Initialize our tracing package
		tracing.InitializeTracer(cfg.ServiceName)

		log.Info(ctx, "Tracing initialized successfully")
	}

	return providers, nil
}

// initializeMetrics sets up metrics with Prometheus exporter.
func initializeMetrics(ctx context.Context, _ string) (*metric.MeterProvider, http.Handler, error) {
	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	// Create meter provider with Prometheus exporter
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(exporter),
	)

	// Use promhttp.Handler() for the default Prometheus registry
	// The OTel Prometheus exporter automatically registers metrics with the default registry
	prometheusHandler := promhttp.Handler()

	log.Debug(ctx, "Metrics provider configured with Prometheus exporter")

	return meterProvider, prometheusHandler, nil
}

// initializeTracing sets up tracing (for now just a basic setup)
// In the future this could be extended with OTLP exporters for Jaeger, etc.
func initializeTracing(ctx context.Context, _ string) *sdktrace.TracerProvider {
	// For now, create a basic tracer provider
	// In production, you'd typically configure with OTLP exporter
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	log.Debug(ctx, "Tracing provider configured (basic setup)")

	return tracerProvider
}

// Shutdown gracefully shuts down OpenTelemetry providers.
func (p *OTelProviders) Shutdown(ctx context.Context) error {
	var errs []error

	if p.MeterProvider != nil {
		if err := p.MeterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown meter provider: %w", err))
		}
	}

	if p.TracerProvider != nil {
		if err := p.TracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown tracer provider: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %v", ErrOTelShutdownFailed, errs)
	}

	return nil
}
