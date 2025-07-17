package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/streaming"
)

// ResponseData holds the necessary data from an HTTP response.
type ResponseData struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// forwardResponse forwards the response to the client.
func forwardResponse(ctx context.Context, writer http.ResponseWriter, resp *ResponseData) {
	// Copy headers
	for key, values := range resp.Headers {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}

	writer.WriteHeader(resp.StatusCode)

	if _, err := writer.Write(resp.Body); err != nil {
		log.Error(ctx, err, "Failed to write response")
	}
}

// fetchUserPreferences retrieves user preferences from Schwab API and returns the response data.
func (p *APIProxy) fetchUserPreferences(ctx context.Context, request *http.Request) (*ResponseData, error) {
	// Read request body if any
	var body io.Reader
	if request.Body != nil {
		body = request.Body
	}

	// Forward to Schwab
	endpoint := request.URL.Path
	if request.URL.RawQuery != "" {
		endpoint = endpoint + "?" + request.URL.RawQuery
	}

	// Copy headers but remove Accept-Encoding to ensure we get uncompressed response
	headers := make(http.Header)

	for key, values := range request.Header {
		if !strings.EqualFold(key, "Accept-Encoding") {
			headers[key] = values
		}
	}

	resp, err := p.schwabClient.Call(ctx, request.Method, endpoint, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to call Schwab API: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return &ResponseData{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
	}, nil
}

// processStreamingMetadata modifies the streaming URL to point to the proxy.
func (p *APIProxy) processStreamingMetadata(prefs *streaming.UserPreferencesResponse, request *http.Request) {
	if len(prefs.StreamerInfo) == 0 {
		return
	}

	// Get the proxy's hostname from the request
	scheme := "wss"
	if request.TLS == nil {
		scheme = "ws"
	}

	// Build the proxy WebSocket URL
	proxyURL := fmt.Sprintf("%s://%s/ws/stream", scheme, request.Host)

	// Update the URL in the response
	for i := range prefs.StreamerInfo {
		prefs.StreamerInfo[i].StreamerSocketURL = proxyURL
	}

	log.Debug(request.Context(), "Modified streaming URL",
		"original_url", "wss://streamer-api.schwab.com/ws",
		"proxy_url", proxyURL,
		"host", request.Host,
	)
}

// modifyAndSendPreferences modifies and sends the user preferences response.
func (p *APIProxy) modifyAndSendPreferences(
	writer http.ResponseWriter,
	request *http.Request,
	resp *ResponseData,
) {
	// Parse response
	var prefs streaming.UserPreferencesResponse

	if err := json.Unmarshal(resp.Body, &prefs); err != nil {
		log.Error(request.Context(), err, "Failed to parse user preferences",
			"body_length", len(resp.Body),
		)

		// Forward original response if parse fails
		forwardResponse(request.Context(), writer, resp)

		return
	}

	// Extract and store metadata if streaming info exists
	p.processStreamingMetadata(&prefs, request)

	if len(prefs.StreamerInfo) > 0 {
		log.Debug(request.Context(), "After processStreamingMetadata",
			"modified_url", prefs.StreamerInfo[0].StreamerSocketURL,
		)
	}

	// Re-encode with modifications
	modified, err := json.Marshal(prefs)
	if err != nil {
		log.Error(request.Context(), err, "Failed to encode modified preferences")
		// Forward original response if encode fails
		forwardResponse(request.Context(), writer, resp)

		return
	}

	// Send modified response
	for key, values := range resp.Headers {
		// Skip Content-Encoding and Content-Length since we're sending uncompressed modified JSON
		if strings.EqualFold(key, "Content-Encoding") || strings.EqualFold(key, "Content-Length") {
			continue
		}

		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(resp.StatusCode)

	if _, err := writer.Write(modified); err != nil {
		log.Error(request.Context(), err, "Failed to write modified response")
	}
}

// handleUserPreferences intercepts and modifies the user preferences response.
func (p *APIProxy) handleUserPreferences(writer http.ResponseWriter, request *http.Request) {
	log.Debug(request.Context(), "handleUserPreferences called",
		"method", request.Method,
		"path", request.URL.Path,
	)

	// Only intercept GET requests
	if request.Method != http.MethodGet {
		p.handleTraderRequest(writer, request)

		return
	}

	// Fetch preferences from Schwab
	resp, err := p.fetchUserPreferences(request.Context(), request)
	if err != nil {
		log.Error(request.Context(), err, "Failed to fetch user preferences")
		http.Error(writer, "Failed to fetch preferences", http.StatusBadGateway)

		return
	}

	// If not successful, forward as-is
	if resp.StatusCode != http.StatusOK {
		forwardResponse(request.Context(), writer, resp)

		return
	}

	// Modify and send the preferences
	p.modifyAndSendPreferences(writer, request, resp)
}

// isUserPreferencesRequest checks if this is a user preferences request.
func isUserPreferencesRequest(path string) bool {
	// Remove query parameters for comparison
	if idx := strings.Index(path, "?"); idx > 0 {
		path = path[:idx]
	}

	// Check if it matches the user preferences endpoint
	return strings.HasSuffix(path, "/userPreference")
}

// interceptableTraderRequest wraps handleTraderRequest to intercept specific endpoints.
func (p *APIProxy) interceptableTraderRequest(writer http.ResponseWriter, request *http.Request) {
	log.Debug(request.Context(), "interceptableTraderRequest called",
		"path", request.URL.Path,
		"is_user_preferences", isUserPreferencesRequest(request.URL.Path),
	)

	// Check if this is a user preferences request
	if isUserPreferencesRequest(request.URL.Path) {
		p.handleUserPreferences(writer, request)

		return
	}

	// Otherwise, forward normally
	p.handleTraderRequest(writer, request)
}
