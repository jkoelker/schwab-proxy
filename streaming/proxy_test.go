package streaming_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/streaming"
)

func TestProxy(t *testing.T) {
	t.Parallel()
	// Mock dependencies
	tokenManager := &mockTokenManager{}

	// Create a minimal auth server for testing
	mockStore := &mockStorage{data: make(map[string]any)}
	signingKey := []byte("test-key-that-is-at-least-32-bytes-long")
	testConfig := &config.Config{
		OAuth2AccessTokenExpiry:  12 * time.Hour,
		OAuth2RefreshTokenExpiry: 7 * 24 * time.Hour,
		OAuth2AuthCodeExpiry:     10 * time.Minute,
	}

	authServer, err := auth.NewServer(mockStore, testConfig, signingKey)
	if err != nil {
		t.Fatalf("Failed to create auth server: %v", err)
	}

	metadataFunc := func() (*streaming.Metadata, error) {
		return &streaming.Metadata{
			CorrelID:   "test-correl",
			CustomerID: "test-customer",
			Channel:    "test-channel",
			FunctionID: "test-function",
			WSEndpoint: "wss://test.example.com/stream",
		}, nil
	}

	// Create proxy
	proxy := streaming.NewProxy(tokenManager, authServer, metadataFunc)

	// Test Start
	ctx := context.Background()

	err = proxy.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Test Stop
	err = proxy.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Test GetConnectionState
	state := proxy.GetConnectionState()
	if state != "disconnected" {
		t.Errorf("Expected disconnected state, got %s", state)
	}

	// Test GetClientCount
	count := proxy.GetClientCount()
	if count != 0 {
		t.Errorf("Expected 0 clients, got %d", count)
	}
}

// Mock implementations.
type mockTokenManager struct{}

func (m *mockTokenManager) GetProviderToken(_ context.Context) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

func (m *mockTokenManager) RefreshProviderToken(ctx context.Context) (*oauth2.Token, error) {
	return m.GetProviderToken(ctx)
}

func (m *mockTokenManager) SaveProviderToken(_ context.Context, _ *oauth2.Token) error {
	return nil
}

func (m *mockTokenManager) StoreProviderToken(_ context.Context, _, _, _ string, _ int) error {
	return nil
}

func (m *mockTokenManager) NeedsProactiveRefresh(_ context.Context) bool {
	return false
}

// Mock storage for auth server.
type mockStorage struct {
	data map[string]any
}

func (m *mockStorage) Get(key string, value any) error {
	if val, ok := m.data[key]; ok {
		// Simple type assertion for test
		switch targetValue := value.(type) {
		case *string:
			str, ok := val.(string)
			if ok {
				*targetValue = str
			}
		case *[]byte:
			b, ok := val.([]byte)
			if ok {
				*targetValue = b
			}
		}

		return nil
	}

	return nil
}

func (m *mockStorage) Set(key string, value any, _ time.Duration) error {
	m.data[key] = value

	return nil
}

func (m *mockStorage) Delete(key string) error {
	delete(m.data, key)

	return nil
}
