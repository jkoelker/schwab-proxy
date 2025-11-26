package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/log"
)

const (
	// httpClientTimeout is the timeout for HTTP client requests.
	httpClientTimeout = 30 * time.Second

	// http transport tuning.
	httpDialTimeout           = 30 * time.Second
	httpDialKeepAlive         = 30 * time.Second
	httpMaxIdleConns          = 100
	httpIdleConnTimeout       = 90 * time.Second
	httpTLSHandshakeTimeout   = 10 * time.Second
	httpExpectContinueTimeout = 1 * time.Second

	// httpClientMaxConnsPerHost limits parallel sockets to a Schwab host to keep
	// stream counts low and avoid server GOAWAYs under load.
	httpClientMaxConnsPerHost = 10

	// httpClientMaxIdleConnsPerHost keeps a small warm pool matching the max
	// active connections so we reuse sockets without over-provisioning.
	httpClientMaxIdleConnsPerHost = httpClientMaxConnsPerHost

	// stateRandomLength is the length of random bytes for state generation.
	stateRandomLength = 32
)

// Sentinel errors for API package.
var (
	ErrNoTokenAvailable = errors.New("no token available; manual authorization required")
	ErrNoStateStored    = errors.New("no state stored")
	ErrStateMismatch    = errors.New("state mismatch")
	ErrNoTokenToRefresh = errors.New("no token available to refresh")
	ErrNoCurrentToken   = errors.New("no token available")
)

// ProviderClient defines the interface for OAuth API providers.
type ProviderClient interface {
	Initialize(ctx context.Context) error
	GetAuthorizationURL() (*url.URL, error)
	ExchangeCode(ctx context.Context, code string) error
	RefreshToken(ctx context.Context) error
	GetToken() (*oauth2.Token, error)
	Call(ctx context.Context, method, endpoint string, body io.Reader, headers http.Header) (*http.Response, error)
}

// SchwabClient handles API requests to Schwab.
type SchwabClient struct {
	config       *config.Config
	httpClient   *http.Client
	tokenService auth.TokenServicer
	tokenMutex   sync.RWMutex
	currentToken *oauth2.Token

	// OAuth2 configuration
	oauth2Config *oauth2.Config

	// OAuth flow state
	codeVerifier string
	state        string
}

// NewSchwabClient creates a new Schwab API client.
func NewSchwabClient(cfg *config.Config, tokenService auth.TokenServicer) *SchwabClient {
	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.SchwabClientID,
		ClientSecret: cfg.SchwabClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.SchwabAuthURL,
			TokenURL: config.SchwabTokenURL,
		},
		RedirectURL: cfg.SchwabRedirectURI,
	}

	client := &SchwabClient{
		config:       cfg,
		httpClient:   newHTTPClient(),
		tokenService: tokenService,
		oauth2Config: oauth2Cfg,
	}

	return client
}

// newHTTPClient builds the shared HTTP client with conservative per-host
// connection limits to stay under Schwab's rate/stream expectations while still
// allowing limited parallelism.
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   httpDialTimeout,
			KeepAlive: httpDialKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          httpMaxIdleConns,
		IdleConnTimeout:       httpIdleConnTimeout,
		TLSHandshakeTimeout:   httpTLSHandshakeTimeout,
		ExpectContinueTimeout: httpExpectContinueTimeout,
		MaxConnsPerHost:       httpClientMaxConnsPerHost,
		MaxIdleConnsPerHost:   httpClientMaxIdleConnsPerHost,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   httpClientTimeout,
	}
}

// Initialize sets up the client and loads/refreshes the token.
func (c *SchwabClient) Initialize(ctx context.Context) error {
	// Try to load existing token
	token, err := c.tokenService.GetProviderToken(ctx)
	if err == nil {
		c.tokenMutex.Lock()
		c.currentToken = token
		c.tokenMutex.Unlock()

		return nil
	}

	return ErrNoTokenAvailable
}

// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// is this really cryptographically secure?, shouldn't it use crypto/rand?
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GetAuthorizationURL initiates the OAuth flow with Schwab.
func (c *SchwabClient) GetAuthorizationURL() (*url.URL, error) {
	// Generate PKCE code verifier
	c.codeVerifier = oauth2.GenerateVerifier()

	// Generate state for CSRF protection
	state, err := generateRandomString(stateRandomLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	c.state = state

	// Build authorization URL with PKCE
	authURL := c.oauth2Config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(c.codeVerifier),
	)

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization URL: %w", err)
	}

	return parsedURL, nil
}

// ValidateState validates the state parameter for CSRF protection.
func (c *SchwabClient) ValidateState(state string) error {
	if c.state == "" {
		return ErrNoStateStored
	}

	if state != c.state {
		return ErrStateMismatch
	}

	return nil
}

// ExchangeCode exchanges the code for a token.
func (c *SchwabClient) ExchangeCode(ctx context.Context, code string) error {
	// Exchange code for token using PKCE verifier
	token, err := c.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(c.codeVerifier),
	)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	// Calculate expires_in from the expiry time
	expiresIn := 0
	if !token.Expiry.IsZero() {
		expiresIn = int(time.Until(token.Expiry).Seconds())
	}

	// Store in token service
	err = c.tokenService.StoreProviderToken(
		ctx,
		token.AccessToken,
		token.TokenType,
		token.RefreshToken,
		expiresIn,
	)
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	// Update current token
	c.tokenMutex.Lock()
	c.currentToken = token
	c.tokenMutex.Unlock()

	return nil
}

// RefreshToken refreshes the current token.
func (c *SchwabClient) RefreshToken(ctx context.Context) error {
	c.tokenMutex.RLock()

	if c.currentToken == nil {
		c.tokenMutex.RUnlock()

		return ErrNoTokenToRefresh
	}

	// Copy the current token
	oldToken := *c.currentToken
	c.tokenMutex.RUnlock()

	// Log refresh token status before refresh
	log.Debug(ctx, "Starting token refresh",
		"has_refresh_token", oldToken.RefreshToken != "",
		"token_expires_at", oldToken.Expiry.Format(time.RFC3339))

	// Use oauth2 TokenSource to refresh
	tokenSource := c.oauth2Config.TokenSource(ctx, &oldToken)

	newToken, err := tokenSource.Token()
	if err != nil {
		// Check for specific refresh token errors
		if strings.Contains(err.Error(), "refresh_token_authentication_error") {
			log.Error(ctx, err, "Refresh token rejected by Schwab - re-authentication required via /setup")
		}

		return fmt.Errorf("token refresh failed: %w", err)
	}

	// Log what we got back
	log.Debug(ctx, "Token refresh response received",
		"new_refresh_token_provided", newToken.RefreshToken != "",
		"refresh_token_changed", newToken.RefreshToken != oldToken.RefreshToken)

	// Calculate expires_in from the expiry time
	expiresIn := 0
	if !newToken.Expiry.IsZero() {
		expiresIn = int(time.Until(newToken.Expiry).Seconds())
	}

	// Store in token service
	err = c.tokenService.StoreProviderToken(
		ctx,
		newToken.AccessToken,
		newToken.TokenType,
		newToken.RefreshToken,
		expiresIn,
	)
	if err != nil {
		return fmt.Errorf("failed to store refreshed token: %w", err)
	}

	// Update current token
	c.tokenMutex.Lock()
	c.currentToken = newToken
	c.tokenMutex.Unlock()

	return nil
}

// Call makes an authenticated API call to Schwab.
func (c *SchwabClient) Call(
	ctx context.Context,
	method,
	endpoint string,
	body io.Reader,
	headers http.Header,
) (*http.Response, error) {
	// Get current token (middleware ensures it's valid)
	c.tokenMutex.RLock()

	if c.currentToken == nil {
		c.tokenMutex.RUnlock()

		return nil, ErrNoCurrentToken
	}

	accessToken := c.currentToken.AccessToken
	c.tokenMutex.RUnlock()

	requestURL := c.buildRequestURL(endpoint)

	// Build request. When body is empty (common for GET), ensure GetBody is set
	// so the http2 transport can automatically retry on GOAWAY/stream errors.
	// Without GetBody, Go refuses to replay the request after the body has been
	// written, leading to errors like "cannot retry ... after Request.Body was
	// written; define Request.GetBody to avoid this error".
	if body == http.NoBody {
		body = nil
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	c.copyHeaders(req, headers)

	// For requests with no body, explicitly provide a GetBody implementation so
	// the transport can transparently retry calls when a connection is closed
	// with GOAWAY/stream errors. Without GetBody, the transport refuses to retry
	// after writing the body (even when it's empty).
	if req.GetBody == nil && (body == nil || body == http.NoBody) {
		req.GetBody = func() (io.ReadCloser, error) {
			return http.NoBody, nil
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}

	return resp, nil
}

// GetToken returns the current OAuth token for health checking.
func (c *SchwabClient) GetToken() (*oauth2.Token, error) {
	c.tokenMutex.RLock()
	defer c.tokenMutex.RUnlock()

	if c.currentToken == nil {
		return nil, ErrNoCurrentToken
	}

	// Return a copy to avoid race conditions
	tokenCopy := *c.currentToken

	return &tokenCopy, nil
}

// buildRequestURL constructs the full API URL from endpoint.
func (c *SchwabClient) buildRequestURL(endpoint string) string {
	requestURL := config.SchwabAPIBase

	// Ensure the endpoint starts with a slash
	if !strings.HasPrefix(endpoint, "/") {
		requestURL += "/"
	}

	return requestURL + endpoint
}

// copyHeaders copies headers from original request, skipping certain headers.
func (c *SchwabClient) copyHeaders(req *http.Request, headers http.Header) {
	for key, values := range headers {
		// Skip certain headers that we don't want to forward
		if key == "Authorization" || key == "Host" {
			continue
		}

		req.Header[key] = values
	}
}
