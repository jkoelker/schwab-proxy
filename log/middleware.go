package log

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	// CorrelationIDHeader is the HTTP header name for correlation IDs.
	CorrelationIDHeader = "X-Correlation-ID"

	// correlationIDByteLength is the length of random bytes for correlation ID generation.
	correlationIDByteLength = 8 // 16 character hex string
)

// WithCorrelationID adds a correlation ID to the logging context.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return WithValues(ctx, "correlation_id", correlationID)
}

// CorrelationIDMiddleware adds correlation IDs to requests for tracing.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		// Check if correlation ID already exists in headers
		correlationID := request.Header.Get(CorrelationIDHeader)

		// Generate a new one if not present
		if correlationID == "" {
			correlationID = generateCorrelationID()
		}

		// Add correlation ID to response headers
		writer.Header().Set(CorrelationIDHeader, correlationID)

		// Add correlation ID to context
		ctx = WithCorrelationID(ctx, correlationID)

		// Continue with the request
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// LoggingOptions holds configuration for the logging middleware.
type LoggingOptions struct {
	DebugHealthChecks bool
}

// WithDebugHealthChecks enables or disables debug logging for health check endpoints.
func WithDebugHealthChecks(enabled bool) func(*LoggingOptions) {
	return func(opts *LoggingOptions) {
		opts.DebugHealthChecks = enabled
	}
}

// LoggingMiddleware logs HTTP requests with structured logging.
func LoggingMiddleware(next http.Handler, opts ...func(*LoggingOptions)) http.Handler {
	// Apply default options
	options := &LoggingOptions{
		DebugHealthChecks: true, // Default to true for backwards compatibility
	}

	// Apply provided options
	for _, opt := range opts {
		opt(options)
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		// Skip logging for health checks if debug is disabled
		isHealthCheck := strings.HasPrefix(request.URL.Path, "/health/")
		if isHealthCheck && !options.DebugHealthChecks {
			next.ServeHTTP(writer, request)

			return
		}

		// Determine log level based on path
		level := LevelInfo
		if isHealthCheck {
			level = LevelDebug
		}

		// Log the incoming request
		Log(ctx, level, "HTTP request started",
			"method", request.Method,
			"path", request.URL.Path,
			"remote_addr", request.RemoteAddr,
			"user_agent", request.Header.Get("User-Agent"),
		)

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: writer, statusCode: http.StatusOK}

		// Continue with the request
		next.ServeHTTP(wrapped, request)

		// Log the response
		Log(ctx, level, "HTTP request completed",
			"method", request.Method,
			"path", request.URL.Path,
			"status_code", wrapped.statusCode,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter

	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// generateCorrelationID creates a new random correlation ID.
func generateCorrelationID() string {
	bytes := make([]byte, correlationIDByteLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple timestamp-based ID if random fails
		return "fallback-id"
	}

	return hex.EncodeToString(bytes)
}
