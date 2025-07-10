package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jkoelker/schwab-proxy/api"
	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/health"
	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/observability"
	"github.com/jkoelker/schwab-proxy/storage"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// tokenClaimsKey is the context key for token claims.
const tokenClaimsKey contextKey = "token_claims"

const (
	invalidTokenHeader      = "WWW-Authenticate"
	invalidTokenHeaderValue = `Bearer error="invalid_token", ` +
		`error_description="The access token provided is expired, revoked, malformed, or invalid"`
)

// APIProxy is the main server that handles API requests.
type APIProxy struct {
	mux           *http.ServeMux
	cfg           *config.Config
	schwabClient  api.ProviderClient
	tokenService  auth.TokenServicer
	clientService *auth.ClientService
	healthHandler *health.HTTPHandler
	otelProviders *observability.OTelProviders
	server        *auth.Server
	storage       *storage.Store
	logger        *slog.Logger

	// Background refresh management
	refreshCancel context.CancelFunc
}

// NewAPIProxy creates a new API proxy server.
func NewAPIProxy(
	cfg *config.Config,
	schwabClient api.ProviderClient,
	tokenService auth.TokenServicer,
	clientService *auth.ClientService,
	store *storage.Store,
	otelProviders *observability.OTelProviders,
) (*APIProxy, error) {
	// Create health checker
	healthChecker := health.NewManager("schwab-proxy-1.0.0")

	// Add storage health check
	healthChecker.AddChecker(health.NewStorageChecker(store))

	// Add provider API health check
	healthChecker.AddChecker(health.NewProviderChecker(schwabClient))

	// Create OAuth2 server
	storageAdapter := auth.NewStorageAdapter(store)

	// Get JWT KDF parameters and derive key
	jwtKDFParams, err := cfg.GetJWTKDFParams()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT KDF parameters: %w", err)
	}

	// Read KDF params file to get JWT salt
	paramsFile, err := storage.ReadKDFParamsFile(cfg.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KDF params file for JWT salt: %w", err)
	}

	// Get the JWT salt
	jwtSalt, err := paramsFile.GetSalt("jwt")
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT salt: %w", err)
	}

	jwtSigningKey, err := jwtKDFParams.DeriveKey(
		[]byte(cfg.JWTSeed),
		jwtSalt,
		auth.JWTKeySize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive JWT signing key: %w", err)
	}

	server, err := auth.NewServer(storageAdapter, cfg, jwtSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 server: %w", err)
	}

	proxy := &APIProxy{
		mux:           http.NewServeMux(),
		cfg:           cfg,
		schwabClient:  schwabClient,
		tokenService:  tokenService,
		clientService: clientService,
		healthHandler: health.NewHTTPHandler(healthChecker),
		otelProviders: otelProviders,
		server:        server,
		storage:       store,
		logger:        slog.Default(),
	}

	// Set up routes
	proxy.setupRoutes()

	// Start background token refresh
	proxy.startBackgroundTokenRefresh()

	return proxy, nil
}

// ServeHTTP implements the http.Handler interface.
func (p *APIProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Middleware is now handled at the server level in main.go
	p.mux.ServeHTTP(w, r)
}

// GetServer returns the OAuth2 server.
func (p *APIProxy) GetServer() *auth.Server {
	return p.server
}

// Shutdown gracefully stops the background token refresh.
func (p *APIProxy) Shutdown() {
	if p.refreshCancel != nil {
		p.refreshCancel()
	}
}

// setupRoutes configures all API routes.
func (p *APIProxy) setupRoutes() {
	// Setup endpoint for Schwab authentication
	p.mux.HandleFunc("GET /setup", p.handleSetup)
	p.mux.HandleFunc("GET /setup/callback", p.handleSetupCallback)

	// Health endpoints
	p.mux.HandleFunc("GET /health/live", p.healthHandler.LivenessHandler)
	p.mux.HandleFunc("GET /health/ready", p.healthHandler.ReadinessHandler)

	// Metrics endpoint (Prometheus format)
	if p.otelProviders != nil && p.otelProviders.PrometheusHTTP != nil {
		p.mux.Handle("GET /metrics", p.otelProviders.PrometheusHTTP)
	}

	// OAuth endpoints - using OAuth2 server
	p.mux.HandleFunc("GET /v1/oauth/authorize", p.handleAuthorizeRequest)
	p.mux.HandleFunc("POST /v1/oauth/authorize", p.handleAuthorizeRequest)
	p.mux.HandleFunc("POST /v1/oauth/token", p.server.HandleTokenRequest)

	// Market data endpoints - following Schwab's structure: /marketdata/v1/...
	p.mux.HandleFunc(
		"/marketdata/v1/",
		p.withTokenValidation(p.withTokenRefresh(p.handleMarketDataRequest)),
	)

	// Trader endpoints - following Schwab's structure: /trader/v1/...
	p.mux.HandleFunc(
		"/trader/v1/",
		p.withTokenValidation(p.withTokenRefresh(p.handleTraderRequest)),
	)

	// Client management endpoints (admin only)
	p.mux.HandleFunc("GET /api/clients", p.withAPIAuth(p.handleListClients))
	p.mux.HandleFunc("POST /api/clients", p.withAPIAuth(p.handleCreateClient))
	p.mux.HandleFunc("GET /api/clients/{id}", p.withAPIAuth(p.handleGetClient))
	p.mux.HandleFunc("PUT /api/clients/{id}", p.withAPIAuth(p.handleUpdateClient))
	p.mux.HandleFunc("DELETE /api/clients/{id}", p.withAPIAuth(p.handleDeleteClient))

	// Approval queue endpoints (admin only)
	p.mux.HandleFunc("GET /api/approvals", p.withAPIAuth(p.handleListApprovals))
	p.mux.HandleFunc("POST /api/approvals/{id}", p.withAPIAuth(p.handleApproveRequest))
	p.mux.HandleFunc("DELETE /api/approvals/{id}", p.withAPIAuth(p.handleDenyRequest))
}

// startBackgroundTokenRefresh starts a goroutine that proactively refreshes the Schwab token.
func (p *APIProxy) startBackgroundTokenRefresh() {
	ctx, cancel := context.WithCancel(context.Background())
	p.refreshCancel = cancel

	go func() {
		log.Info(ctx, "Starting background token refresh ticker", "check_interval", p.cfg.TokenRefreshInterval.String())

		ticker := time.NewTicker(p.cfg.TokenRefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info(ctx, "Background token refresh stopped")

				return
			case <-ticker.C:
				log.Info(
					ctx, "Background token refresh check triggered",
					"next_check_in", p.cfg.TokenRefreshInterval.String(),
				)

				if p.tokenService.NeedsProactiveRefresh(ctx) {
					log.Info(ctx, "Token needs proactive refresh, initiating refresh")

					err := p.schwabClient.RefreshToken(ctx)
					if err != nil {
						log.Error(ctx, err, "Background token refresh failed")
					} else {
						log.Info(ctx, "Background token refresh successful")
					}
				} else {
					log.Info(ctx, "Token does not need refresh yet")
				}
			}
		}
	}()
}

// withTokenValidation middleware validates client tokens for API requests.
func (p *APIProxy) withTokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// Extract the access token from the Authorization header
		authHeader := request.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(writer, "Authorization header required", http.StatusUnauthorized)

			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(
				writer,
				"Invalid authorization format, Bearer token required",
				http.StatusUnauthorized,
			)

			return
		}

		// Extract the token
		tokenString := authHeader[7:]

		// Validate the token using fosite's access token validation
		ctx := request.Context()

		clientID, scopes, err := p.server.ValidateAccessToken(ctx, tokenString)
		if err != nil {
			if p.cfg.DebugLogging {
				// Log only the non-sensitive prefix part (before the signature)
				tokenPrefix := tokenString
				if dotIndex := strings.IndexByte(tokenString, '.'); dotIndex > 0 {
					tokenPrefix = tokenString[:dotIndex]
				}

				log.Debug(ctx, "Token validation failed",
					"error", err.Error(),
					"token_prefix", tokenPrefix,
				)
			}

			// Return RFC 6750 compliant Bearer token error response
			writer.Header().Set(invalidTokenHeader, invalidTokenHeaderValue)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnauthorized)

			errorResponse := map[string]string{
				"error":             "invalid_token",
				"error_description": "The access token provided is expired, revoked, malformed, or invalid",
			}

			if encodeErr := json.NewEncoder(writer).Encode(errorResponse); encodeErr != nil {
				log.Error(ctx, encodeErr, "Failed to encode error response")
			}

			return
		}

		// Create token claims from the validation result for rate limiting
		claims := &auth.TokenClaims{
			ClientID: clientID,
			Scopes:   scopes,
		}

		// Set claims in request context for later use
		ctxWithClaims := context.WithValue(ctx, tokenClaimsKey, claims)

		// Continue to the next handler with the updated context
		next(writer, request.WithContext(ctxWithClaims))
	}
}

// withTokenRefresh wraps a handler with token refresh middleware.
func (p *APIProxy) withTokenRefresh(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// Check if token is available and not expired
		token, err := p.tokenService.GetProviderToken(request.Context())
		if err != nil || !token.Valid() {
			// Token expired or not available, try to refresh
			err = p.schwabClient.RefreshToken(request.Context())
			if err != nil {
				http.Error(writer, "Authentication required", http.StatusUnauthorized)

				return
			}
		}

		// Continue to the next handler
		next(writer, request)
	}
}

// handleSetup initiates the Schwab OAuth flow.
func (p *APIProxy) handleSetup(writer http.ResponseWriter, request *http.Request) {
	authURL, err := p.schwabClient.GetAuthorizationURL()
	if err != nil {
		http.Error(writer, "Failed to create authorization URL", http.StatusInternalServerError)

		return
	}

	// In a real application, you might want to show a page with instructions
	// For simplicity, we'll just redirect
	http.Redirect(writer, request, authURL.String(), http.StatusFound)
}

// handleSetupCallback processes the callback from Schwab OAuth.
func (p *APIProxy) handleSetupCallback(writer http.ResponseWriter, request *http.Request) {
	// Validate state parameter for CSRF protection
	state := request.URL.Query().Get("state")
	if state == "" {
		http.Error(writer, "No state parameter provided", http.StatusBadRequest)

		return
	}

	// Type assert to access ValidateState method
	schwabClient, ok := p.schwabClient.(*api.SchwabClient)
	if !ok {
		http.Error(writer, "Invalid client type", http.StatusInternalServerError)

		return
	}

	if err := schwabClient.ValidateState(state); err != nil {
		http.Error(writer, "Invalid state parameter", http.StatusBadRequest)

		return
	}

	code := request.URL.Query().Get("code")
	if code == "" {
		http.Error(writer, "No authorization code provided", http.StatusBadRequest)

		return
	}

	err := p.schwabClient.ExchangeCode(request.Context(), code)
	if err != nil {
		log.Error(request.Context(), err, "Failed to exchange authorization code")
		http.Error(
			writer,
			"Failed to exchange authorization code",
			http.StatusInternalServerError,
		)

		return
	}

	// Initialize the client with the new token
	err = p.schwabClient.Initialize(request.Context())
	if err != nil {
		log.Error(request.Context(), err, "Failed to initialize Schwab client")
		http.Error(writer, "Failed to initialize client", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "text/html")

	if _, err := writer.Write(
		[]byte("<h1>Setup Complete</h1><p>You can now close this window.</p>"),
	); err != nil {
		log.Error(request.Context(), err, "Failed to write response")
		http.Error(writer, "Failed to write response", http.StatusInternalServerError)

		return
	}
}

// handleMarketDataRequest handles market data API requests.
func (p *APIProxy) handleMarketDataRequest(writer http.ResponseWriter, request *http.Request) {
	// Just forward the request as-is with the full path
	endpoint := request.URL.Path
	if request.URL.RawQuery != "" {
		endpoint = endpoint + "?" + request.URL.RawQuery
	}

	if p.cfg.DebugLogging {
		// Get token claims if available
		claims, ok := request.Context().Value(tokenClaimsKey).(*auth.TokenClaims)
		if ok {
			log.Debug(request.Context(), "Market data request forwarding",
				"client_id", claims.ClientID,
				"method", request.Method,
				"endpoint", endpoint,
			)
		} else {
			log.Debug(request.Context(), "Market data request forwarding",
				"method", request.Method,
				"endpoint", endpoint,
			)
		}
	}

	p.forwardRequest(writer, request, endpoint)
}

// handleTraderRequest handles trader API requests.
func (p *APIProxy) handleTraderRequest(writer http.ResponseWriter, request *http.Request) {
	// Just forward the request as-is with the full path
	endpoint := request.URL.Path
	if request.URL.RawQuery != "" {
		endpoint = endpoint + "?" + request.URL.RawQuery
	}

	if p.cfg.DebugLogging {
		// Get token claims if available
		claims, ok := request.Context().Value(tokenClaimsKey).(*auth.TokenClaims)
		if ok {
			log.Debug(request.Context(), "Trader request forwarding",
				"client_id", claims.ClientID,
				"method", request.Method,
				"endpoint", endpoint,
			)
		} else {
			log.Debug(request.Context(), "Trader request forwarding",
				"method", request.Method,
				"endpoint", endpoint,
			)
		}
	}

	p.forwardRequest(writer, request, endpoint)
}

// forwardRequest handles the common forwarding logic for all API requests.
func (p *APIProxy) forwardRequest(writer http.ResponseWriter, request *http.Request, endpoint string) {
	// Read request body
	var body io.Reader
	if request.Body != nil {
		body = request.Body
	}

	// Make the API call to Schwab
	resp, err := p.schwabClient.Call(request.Context(), request.Method, endpoint, body, request.Header)
	if err != nil {
		log.Error(request.Context(), err, "API call failed")
		http.Error(writer, "API call failed", http.StatusInternalServerError)

		return
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	// Copy response headers
	for k, values := range resp.Header {
		writer.Header()[k] = values
	}

	// Set the status code
	writer.WriteHeader(resp.StatusCode)

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error(request.Context(), err, "Error reading response body",
			"method", request.Method,
			"endpoint", endpoint,
		)

		return
	}

	// Log error responses for debugging
	if resp.StatusCode >= 400 && p.cfg.DebugLogging {
		log.Debug(request.Context(), "API error response",
			"status_code", resp.StatusCode,
			"method", request.Method,
			"endpoint", endpoint,
			"response_body", string(respBody),
		)
	}

	// Write the response body
	if _, err := writer.Write(respBody); err != nil {
		// Log error but continue since headers and status have already been sent
		log.Error(request.Context(), err, "Error writing response body",
			"method", request.Method,
			"endpoint", endpoint,
		)
	}

	if p.cfg.DebugLogging {
		log.Debug(request.Context(), "API response forwarded",
			"status_code", resp.StatusCode,
			"method", request.Method,
			"endpoint", endpoint,
		)
	}
}
