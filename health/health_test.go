package health_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/health"
	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/storage"
)

const (
	testVersion     = "test-version"
	providerAPIName = "provider_api"
)

var errMockNotImplemented = errors.New("mock method not implemented")

func TestManager_Liveness(t *testing.T) {
	t.Parallel()

	checker := health.NewManager(testVersion)

	response := checker.CheckLiveness(t.Context())

	if response.Status != health.StatusHealthy {
		t.Errorf("Expected healthy status, got %s", response.Status)
	}

	if response.Version != testVersion {
		t.Errorf("Expected version 'test-version', got %s", response.Version)
	}

	if len(response.Checks) != 1 {
		t.Errorf("Expected 1 check, got %d", len(response.Checks))
	}
}

func TestStorageChecker(t *testing.T) {
	t.Parallel()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-health-test")

	// Create temporary database for testing
	tempDir := t.TempDir()

	store, err := storage.NewStore(tempDir, nil)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	defer func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	}()

	checker := health.NewStorageChecker(store)

	if checker.Name() != "storage" {
		t.Errorf("Expected name 'storage', got %s", checker.Name())
	}

	check := checker.Check(t.Context())

	if check.Status != health.StatusHealthy {
		t.Errorf("Expected healthy status, got %s: %s", check.Status, check.Error)
	}

	if check.Name != "storage" {
		t.Errorf("Expected name 'storage', got %s", check.Name)
	}
}

// MockProviderClient for testing.
type MockProviderClient struct{}

func (m *MockProviderClient) Initialize(_ context.Context) error { return nil }
func (m *MockProviderClient) GetAuthorizationURL() (*url.URL, error) {
	return nil, errMockNotImplemented
}
func (m *MockProviderClient) ExchangeCode(_ context.Context, _ string) error { return nil }
func (m *MockProviderClient) RefreshToken(_ context.Context) error           { return nil }
func (m *MockProviderClient) Call(_ context.Context, _, _ string, _ io.Reader, _ http.Header) (*http.Response, error) {
	return nil, errMockNotImplemented
}

func (m *MockProviderClient) GetToken() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "test-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func TestProviderChecker(t *testing.T) {
	t.Parallel()

	mockClient := &MockProviderClient{}
	checker := health.NewProviderChecker(mockClient)

	if checker.Name() != providerAPIName {
		t.Errorf("Expected name 'provider_api', got %s", checker.Name())
	}

	check := checker.Check(t.Context())

	if check.Status != health.StatusHealthy {
		t.Errorf("Expected healthy status, got %s: %s", check.Status, check.Error)
	}

	if check.Name != providerAPIName {
		t.Errorf("Expected name 'provider_api', got %s", check.Name)
	}
}

func TestHTTPHandler_Liveness(t *testing.T) {
	t.Parallel()

	checker := health.NewManager(testVersion)
	handler := health.NewHTTPHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	recorder := httptest.NewRecorder()

	handler.LivenessHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", contentType)
	}
}

func TestHTTPHandler_Readiness(t *testing.T) {
	t.Parallel()

	checker := health.NewManager(testVersion)
	handler := health.NewHTTPHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	recorder := httptest.NewRecorder()

	handler.ReadinessHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", contentType)
	}
}

// DegradedChecker always returns degraded status for testing.
type DegradedChecker struct{}

func (d *DegradedChecker) Name() string {
	return "degraded_test"
}

func (d *DegradedChecker) Check(_ context.Context) health.Check {
	return health.Check{
		Name:        "degraded_test",
		Status:      health.StatusDegraded,
		Message:     "Alrecorderays degraded for testing",
		LastChecked: time.Now(),
		Duration:    0,
	}
}
