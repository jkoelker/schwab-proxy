package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/api"
	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/metrics"
)

// Mock token service for testing.
type mockTokenService struct {
	tokens        map[string]*oauth2.Token
	providerToken *oauth2.Token
}

func (m *mockTokenService) ValidateToken(_ string) (*auth.TokenClaims, error) {
	return nil, nil //nolint:nilnil // Not needed for these tests
}

func (m *mockTokenService) StoreProviderToken(
	_ context.Context,
	accessToken,
	tokenType,
	refreshToken string,
	expiresIn int,
) error {
	m.providerToken = &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
	}

	return nil
}

func (m *mockTokenService) GetProviderToken(_ context.Context) (*oauth2.Token, error) {
	if m.providerToken == nil {
		return nil, badger.ErrKeyNotFound
	}

	return m.providerToken, nil
}

func (m *mockTokenService) DeleteProviderToken() error {
	m.providerToken = nil

	return nil
}

func (m *mockTokenService) NeedsProactiveRefresh(_ context.Context) bool {
	if m.providerToken == nil {
		return true
	}

	// For testing, assume refresh is needed if token expires in less than 3 days
	return time.Until(m.providerToken.Expiry) < 72*time.Hour
}

func createTestConfig() *config.Config {
	return &config.Config{
		SchwabClientID:     "test-client-id",
		SchwabClientSecret: "test-client-secret",
		SchwabRedirectURI:  "http://localhost:8080/callback",
	}
}

func createTestSchwabClient(t *testing.T) (*api.SchwabClient, *mockTokenService) {
	t.Helper()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-api-test")

	cfg := createTestConfig()
	tokenService := &mockTokenService{
		tokens: make(map[string]*oauth2.Token),
	}

	client := api.NewSchwabClient(cfg, tokenService)

	return client, tokenService
}

func TestNewSchwabClient(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	tokenService := &mockTokenService{tokens: make(map[string]*oauth2.Token)}

	client := api.NewSchwabClient(cfg, tokenService)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	// Test that client can be initialized (tests internal fields indirectly)
	err := client.Initialize(t.Context())
	if err == nil {
		t.Error("Expected Initialize to fail without token")
	}
}

func TestSchwabClient_Initialize(t *testing.T) {
	t.Parallel()

	client, tokenService := createTestSchwabClient(t)

	t.Run("WithExistingToken", func(t *testing.T) {
		t.Parallel()

		// Set up existing token
		tokenService.providerToken = &oauth2.Token{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			RefreshToken: "test-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}

		err := client.Initialize(t.Context())
		if err != nil {
			t.Fatalf("Expected Initialize to succeed with existing token: %v", err)
		}

		// Test that token is available by getting it
		token, err := client.GetToken()
		if err != nil {
			t.Error("Expected token to be available after initialization")
		}

		if token == nil {
			t.Error("Expected current token to be set")
		}
	})

	t.Run("WithoutToken", func(t *testing.T) {
		t.Parallel()

		client, _ := createTestSchwabClient(t)

		err := client.Initialize(t.Context())
		if err == nil {
			t.Error("Expected Initialize to fail without token")
		}

		expectedMsg := "no token available; manual authorization required"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
		}
	})
}

func TestSchwabClient_GetAuthorizationURL(t *testing.T) {
	t.Parallel()

	client, _ := createTestSchwabClient(t)

	authURL, err := client.GetAuthorizationURL()
	if err != nil {
		t.Fatalf("Failed to get authorization URL: %v", err)
	}

	if authURL == nil {
		t.Fatal("Expected authorization URL to be returned")
	}

	// Check URL components - use the test config values directly
	cfg := createTestConfig()
	if !strings.Contains(authURL.String(), cfg.SchwabClientID) {
		t.Error("Expected client ID in authorization URL")
	}

	// URL encode the redirect URI for comparison
	if !strings.Contains(authURL.String(), "localhost") {
		t.Error("Expected redirect URI in authorization URL")
	}

	if !strings.Contains(authURL.String(), "response_type=code") {
		t.Error("Expected response_type=code in authorization URL")
	}
}

func TestSchwabClient_GetToken(t *testing.T) {
	t.Parallel()

	client, tokenService := createTestSchwabClient(t)

	t.Run("WithToken", func(t *testing.T) {
		t.Parallel()

		// Set up token
		tokenService.providerToken = &oauth2.Token{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			RefreshToken: "test-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}
		// Initialize client with the token
		err := client.Initialize(t.Context())
		if err != nil {
			t.Fatalf("Failed to initialize client: %v", err)
		}

		token, err := client.GetToken()
		if err != nil {
			t.Fatalf("Failed to get token: %v", err)
		}

		if token.AccessToken != "test-access-token" {
			t.Errorf("Expected access token 'test-access-token', got '%s'", token.AccessToken)
		}
	})

	t.Run("WithoutToken", func(t *testing.T) {
		t.Parallel()

		client, _ := createTestSchwabClient(t)

		_, err := client.GetToken()
		if err == nil {
			t.Error("Expected error when getting token without current token")
		}

		expectedMsg := "no token available"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
		}
	})
}

func TestSchwabClient_CallWithoutToken(t *testing.T) {
	t.Parallel()

	client, _ := createTestSchwabClient(t)

	// Test API call without token - should fail
	resp, err := client.Call(t.Context(), "GET", "/test/endpoint", nil, nil)
	if resp != nil {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}

	if err == nil {
		t.Error("Expected error when making API call without token")
	}

	expectedMsg := "no token available"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
	}
}

func TestSchwabClient_URLBuilding(t *testing.T) {
	t.Parallel()

	client, tokenService := createTestSchwabClient(t)

	// Set up token so we can test URL building
	tokenService.providerToken = &oauth2.Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}
	// Initialize the client with the token
	err := client.Initialize(t.Context())
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	t.Run("EndpointWithLeadingSlash", func(t *testing.T) {
		t.Parallel()

		endpoint := "/trader/v1/accounts"
		expectedURL := config.SchwabAPIBase + endpoint

		resp, err := client.Call(t.Context(), "GET", endpoint, nil, nil)
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Failed to close response body: %v", err)
			}
		}

		if err != nil {
			t.Fatalf("Expected successful call for endpoint '%s', got error: %v", endpoint, err)
		}

		if !strings.Contains(resp.Request.URL.String(), expectedURL) {
			t.Errorf("Expected URL '%s', got '%s'", expectedURL, resp.Request.URL.String())
		}
	})

	t.Run("EndpointWithoutLeadingSlash", func(t *testing.T) {
		t.Parallel()

		endpoint := "trader/v1/accounts"
		expectedURL := config.SchwabAPIBase + "/" + endpoint

		resp, err := client.Call(t.Context(), "GET", endpoint, nil, nil)
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Failed to close response body: %v", err)
			}
		}

		if err != nil {
			t.Fatalf("Expected successful call for endpoint '%s', got error: %v", endpoint, err)
		}

		if !strings.Contains(resp.Request.URL.String(), expectedURL) {
			t.Errorf("Expected URL '%s', got '%s'", expectedURL, resp.Request.URL.String())
		}
	})
}
