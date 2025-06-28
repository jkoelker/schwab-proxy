package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
)

const (
	// httpClientTimeout is the timeout for HTTP client requests.
	httpClientTimeout = 30 * time.Second

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
		httpClient:   &http.Client{Timeout: httpClientTimeout},
		tokenService: tokenService,
		oauth2Config: oauth2Cfg,
	}

	return client
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

	// Use oauth2 TokenSource to refresh
	tokenSource := c.oauth2Config.TokenSource(ctx, &oldToken)

	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

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

	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setDefaultHeaders(req, accessToken, method)
	c.copyHeaders(req, headers)

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

// setDefaultHeaders sets required headers for Schwab API requests.
func (c *SchwabClient) setDefaultHeaders(req *http.Request, accessToken, method string) {
	// Add authorization header - always use "Bearer" for Schwab API
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Add required headers
	req.Header.Set("Accept", "application/json")

	// Add content type if not present
	if req.Header.Get("Content-Type") == "" && method != "GET" && method != "DELETE" {
		req.Header.Set("Content-Type", "application/json")
	}
}

// copyHeaders copies headers from original request, skipping certain headers.
func (c *SchwabClient) copyHeaders(req *http.Request, headers http.Header) {
	for key, values := range headers {
		// Skip certain headers that we don't want to forward
		if key == "Authorization" || key == "Host" {
			continue
		}

		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}
