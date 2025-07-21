package observability

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/middleware"
	"github.com/jkoelker/schwab-proxy/tracing"
)

// HTTP status code constants.
const (
	statusCodeClientError = 400 // Client error threshold (4xx)
	statusCodeServerError = 500 // Server error threshold (5xx)
)

// MetricsMiddleware instruments HTTP requests with metrics.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		start := time.Now()

		// Create a response writer wrapper to capture status code and size
		wrapped := &responseWriter{ResponseWriter: writer, statusCode: http.StatusOK}

		// Record the request
		next.ServeHTTP(wrapped, request)

		// Calculate duration
		duration := time.Since(start)

		// Extract path pattern for better metric grouping
		// For now, use the raw path - in production you'd want to extract route patterns
		endpoint := request.URL.Path
		method := request.Method
		statusCode := strconv.Itoa(wrapped.statusCode)

		// Record HTTP metrics
		metrics.RecordCounter(ctx, "http_requests_total", 1,
			"method", method,
			"endpoint", endpoint,
			"status_code", statusCode,
		)

		metrics.RecordHistogram(ctx, "http_request_duration_ms", float64(duration.Milliseconds()),
			"method", method,
			"endpoint", endpoint,
			"status_code", statusCode,
		)

		// Record response size if available
		if wrapped.bytesWritten > 0 {
			metrics.RecordHistogram(ctx, "http_response_size_bytes", float64(wrapped.bytesWritten),
				"method", method,
				"endpoint", endpoint,
				"status_code", statusCode,
			)
		}
	})
}

// TracingMiddleware instruments HTTP requests with distributed tracing.
func TracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		// Start a span for the HTTP request
		spanName := request.Method + " " + request.URL.Path
		ctx, span := tracing.StartSpan(ctx, spanName)

		defer span.End()

		// Add request attributes to the span
		tracing.SetAttributes(ctx,
			"http.method", request.Method,
			"http.url", request.URL.String(),
			"http.scheme", request.URL.Scheme,
			"http.host", request.Host,
			"http.user_agent", request.Header.Get("User-Agent"),
			"http.remote_addr", middleware.GetRealIP(request),
		)

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: writer, statusCode: http.StatusOK}

		// Continue with the request
		next.ServeHTTP(wrapped, request.WithContext(ctx))

		// Add response attributes to the span
		tracing.SetAttributes(ctx,
			"http.status_code", strconv.Itoa(wrapped.statusCode),
		)

		if wrapped.bytesWritten > 0 {
			tracing.SetAttributes(ctx,
				"http.response_size", strconv.FormatInt(wrapped.bytesWritten, 10),
			)
		}

		// Set span status based on HTTP status code
		if wrapped.statusCode >= statusCodeClientError {
			tracing.SetAttributes(ctx, "error", "true")

			if wrapped.statusCode >= statusCodeServerError {
				// Server errors are considered span errors
				tracing.SetError(ctx, &httpError{
					statusCode: wrapped.statusCode,
					message:    http.StatusText(wrapped.statusCode),
				})
			}
		} else {
			tracing.SetOK(ctx)
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture response metrics.
type responseWriter struct {
	http.ResponseWriter

	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	bytesWritten, err := rw.ResponseWriter.Write(data)
	rw.bytesWritten += int64(bytesWritten)

	if err != nil {
		return bytesWritten, fmt.Errorf("failed to write response data: %w", err)
	}

	return bytesWritten, nil
}

// Hijack implements the http.Hijacker interface to support WebSocket upgrades.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buf, err := middleware.HijackConnection(rw.ResponseWriter, &rw.statusCode)
	if err != nil {
		return nil, nil, fmt.Errorf("error hijacking connection: %w", err)
	}

	return conn, buf, nil
}

// httpError represents an HTTP error for tracing.
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return e.message
}
