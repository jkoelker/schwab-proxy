package middleware

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrHijackNotSupported is returned when the ResponseWriter does not support hijacking.
var ErrHijackNotSupported = errors.New("ResponseWriter does not support hijacking")

// HijackConnection hijacks the underlying connection from a ResponseWriter for WebSocket upgrades.
// It sets statusCode to 101 (Switching Protocols) and returns the hijacked connection.
func HijackConnection(w http.ResponseWriter, statusCode *int) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, ErrHijackNotSupported
	}

	// Set status code to 101 for WebSocket upgrades
	if statusCode != nil {
		*statusCode = http.StatusSwitchingProtocols
	}

	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hijack connection: %w", err)
	}

	return conn, buf, nil
}

// GetRealIP extracts the real client IP from the request, checking various headers.
func GetRealIP(req *http.Request) string {
	// Check X-Real-IP header first (single IP)
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Check X-Forwarded-For header (comma-separated list, first is original client)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}

		return strings.TrimSpace(xff)
	}

	// Check CF-Connecting-IP for Cloudflare
	if ip := req.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}

	// Check True-Client-IP for Cloudflare Enterprise
	if ip := req.Header.Get("True-Client-Ip"); ip != "" {
		return ip
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If splitting fails, return the whole RemoteAddr
		return req.RemoteAddr
	}

	return host
}
