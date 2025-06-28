package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/proxy"
	"github.com/jkoelker/schwab-proxy/storage"
)

// MockProviderClient implements api.ProviderClient for testing.
type MockProviderClient struct {
	initialized bool
}

func (m *MockProviderClient) Initialize(_ context.Context) error {
	m.initialized = true

	return nil
}

func (m *MockProviderClient) GetAuthorizationURL() (*url.URL, error) {
	authURL, err := url.Parse("https://mock.auth.url")
	if err != nil {
		return nil, fmt.Errorf("failed to parse mock auth URL: %w", err)
	}

	return authURL, nil
}

func (m *MockProviderClient) ExchangeCode(_ context.Context, _ string) error {
	return nil
}

func (m *MockProviderClient) RefreshToken(_ context.Context) error {
	return nil
}

func (m *MockProviderClient) GetToken() (*oauth2.Token, error) {
	// Return a mock token for testing
	return &oauth2.Token{
		AccessToken:  "mock-access-token",
		TokenType:    "Bearer",
		RefreshToken: "mock-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func (m *MockProviderClient) Call(_ context.Context, _, _ string, _ io.Reader, _ http.Header) (*http.Response, error) {
	// Create a mock response
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
		Header:     make(http.Header),
	}

	return resp, nil
}

// Test helper to create test proxy.
func createTestProxy(t *testing.T) (*proxy.APIProxy, func()) {
	t.Helper()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-test")

	// Create temp directory for test database
	tempDir := t.TempDir()

	// Create test config
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1",
		Port:        8080,
		DataPath:    tempDir,
		AdminAPIKey: "test-admin-key",
		StorageSeed: "test-storage-seed-32-bytes-xxxxx",
		JWTSeed:     "test-jwt-seed-32-bytes-xxxxxxxxx",
		KDFSpec:     "pbkdf2:default", // Use PBKDF2 for faster tests
	}

	ctx := t.Context()

	// Create storage with migration support to generate KDF params file
	kdfParams, err := cfg.GetStorageKDFParams()
	if err != nil {
		t.Fatalf("Failed to get KDF params: %v", err)
	}

	store, err := storage.NewStoreWithMigration(ctx, tempDir, []byte(cfg.StorageSeed), kdfParams)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create services
	tokenService := auth.NewTokenService(store)
	clientService := auth.NewClientService(store)
	mockProvider := &MockProviderClient{}

	// Create proxy with nil OTel providers for testing
	proxyInstance, err := proxy.NewAPIProxy(cfg, mockProvider, tokenService, clientService, store, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	cleanup := func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	}

	return proxyInstance, cleanup
}

func TestClientManagementAPI(t *testing.T) {
	t.Parallel()

	proxyInstance, cleanup := createTestProxy(t)
	t.Cleanup(cleanup)

	testCreateClient(t, proxyInstance)
	testListClients(t, proxyInstance)
	testUnauthorizedAccess(t, proxyInstance)
}

func testCreateClient(t *testing.T, proxyInstance *proxy.APIProxy) {
	t.Helper()

	// Test creating a client
	t.Run("CreateClient", func(t *testing.T) {
		t.Parallel()

		createReq := proxy.CreateClientRequest{
			Name:        "Test Client",
			Description: "Test Description",
			RedirectURI: "http://localhost:3000/callback",
			Scopes:      []string{"read", "write"},
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/clients", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer test-admin-key")
		req.Header.Set("Content-Type", "application/json")

		writer := httptest.NewRecorder()
		proxyInstance.ServeHTTP(writer, req)

		if writer.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d", http.StatusCreated, writer.Code)
		}

		var response proxy.ClientWithSecretResponse
		if err := json.NewDecoder(writer.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response.Name != createReq.Name {
			t.Errorf("Expected name '%s', got '%s'", createReq.Name, response.Name)
		}

		if response.Secret == "" {
			t.Error("Expected secret to be returned")
		}
	})
}

func testListClients(t *testing.T, proxyInstance *proxy.APIProxy) {
	t.Helper()

	// Test listing clients
	t.Run("ListClients", func(t *testing.T) {
		t.Parallel()

		// First create a client to ensure we have something to list
		createReq := proxy.CreateClientRequest{
			Name:        "List Test Client",
			Description: "Client for list test",
			RedirectURI: "http://localhost:3000/callback",
			Scopes:      []string{"read"},
		}

		body, _ := json.Marshal(createReq)
		createRequest := httptest.NewRequest(http.MethodPost, "/api/clients", bytes.NewBuffer(body))
		createRequest.Header.Set("Authorization", "Bearer test-admin-key")
		createRequest.Header.Set("Content-Type", "application/json")

		createWriter := httptest.NewRecorder()
		proxyInstance.ServeHTTP(createWriter, createRequest)

		if createWriter.Code != http.StatusCreated {
			t.Fatalf("Failed to create client for list test: %d", createWriter.Code)
		}

		// Now test listing clients
		req := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
		req.Header.Set("Authorization", "Bearer test-admin-key")

		writer := httptest.NewRecorder()
		proxyInstance.ServeHTTP(writer, req)

		if writer.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, writer.Code)
		}

		var response []proxy.ClientResponse
		if err := json.NewDecoder(writer.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(response) == 0 {
			t.Error("Expected at least one client")
		}

		// Verify our created client is in the list
		found := false

		for _, client := range response {
			if client.Name == createReq.Name {
				found = true

				break
			}
		}

		if !found {
			t.Error("Created client not found in list")
		}
	})
}

func testUnauthorizedAccess(t *testing.T, proxyInstance *proxy.APIProxy) {
	t.Helper()

	// Test unauthorized access
	t.Run("UnauthorizedAccess", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
		// No auth header

		writer := httptest.NewRecorder()
		proxyInstance.ServeHTTP(writer, req)

		if writer.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, writer.Code)
		}
	})
}

func TestFositeOAuth2(t *testing.T) {
	t.Parallel()

	proxyInstance, cleanup := createTestProxy(t)
	t.Cleanup(cleanup)

	// Test that Fosite endpoints are available
	t.Run("TokenEndpointAvailable", func(t *testing.T) {
		t.Parallel()
		// Test client credentials grant (which we have enabled)
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", "test-client")
		data.Set("client_secret", "test-secret")

		req := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		writer := httptest.NewRecorder()
		proxyInstance.ServeHTTP(writer, req)

		// For now, just verify the endpoint responds (may fail due to client not being registered)
		// The important thing is that it's not returning "not implemented"
		if writer.Code == http.StatusNotImplemented {
			t.Error("OAuth2 endpoint should not return 'not implemented'")
		}

		t.Logf("OAuth2 endpoint response: %d - %s", writer.Code, writer.Body.String())
	})

	// Test that authorization endpoint is available (for authorization code flow)
	t.Run("AuthorizeEndpointAvailable", func(t *testing.T) {
		t.Parallel()

		// Test authorization endpoint
		url := "/v1/oauth/authorize?response_type=code&client_id=test-client" +
			"&redirect_uri=http://localhost:8080/callback&state=test-state"
		req := httptest.NewRequest(http.MethodGet, url, nil)

		writer := httptest.NewRecorder()
		proxyInstance.ServeHTTP(writer, req)

		// For now, just verify the endpoint responds (may fail due to client not being registered)
		// The important thing is that it's not returning "not implemented"
		if writer.Code == http.StatusNotImplemented {
			t.Error("OAuth2 authorize endpoint should not return 'not implemented'")
		}

		t.Logf("OAuth2 authorize endpoint response: %d - %s", writer.Code, writer.Body.String())
	})
}

// TestRFC6750BearerTokenError tests that invalid token responses follow RFC 6750 format.
func TestRFC6750BearerTokenError(t *testing.T) {
	t.Parallel()

	proxyInstance, cleanup := createTestProxy(t)
	t.Cleanup(cleanup)

	// Test invalid token on market data endpoint
	req := httptest.NewRequest(http.MethodGet, "/marketdata/v1/quotes", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	recorder := httptest.NewRecorder()
	proxyInstance.ServeHTTP(recorder, req)

	// Verify RFC 6750 compliant response
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", recorder.Code)
	}

	// Check WWW-Authenticate header
	wwwAuth := recorder.Header().Get("WWW-Authenticate")
	expected := `Bearer error="invalid_token"`

	if !strings.Contains(wwwAuth, expected) {
		t.Errorf("Expected WWW-Authenticate header to contain: %s, got: %s", expected, wwwAuth)
	}

	// Check Content-Type header
	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type: application/json, got: %s", contentType)
	}

	// Parse and verify JSON error response
	var errorResponse map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to parse error response JSON: %v", err)
	}

	if errorResponse["error"] != "invalid_token" {
		t.Errorf("Expected error: invalid_token, got: %s", errorResponse["error"])
	}

	expectedDesc := "The access token provided is expired, revoked, malformed, or invalid"
	if errorResponse["error_description"] != expectedDesc {
		t.Errorf("Expected error_description: %s, got: %s", expectedDesc, errorResponse["error_description"])
	}

	t.Logf("RFC 6750 Bearer token error response verified: %d - %s", recorder.Code, recorder.Body.String())
}
