package auth_test

import (
	"testing"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/storage"
)

func createTestStore(t *testing.T) (*storage.Store, func()) {
	t.Helper()
	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-auth-test")

	tempDir := t.TempDir()
	testKey := []byte("test-encryption-key-32-bytes-xxx")

	store, err := storage.NewStore(tempDir, testKey)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	cleanup := func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	}

	return store, cleanup
}

func TestClientServiceCreateClient(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	client, err := service.CreateClient(
		t.Context(),
		"Test Client",
		"Test Description",
		"http://localhost:3000/callback",
		[]string{"read", "write"},
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client.ID == "" {
		t.Error("Expected client ID to be set")
	}

	if len(client.Secret) == 0 {
		t.Error("Expected client secret to be set")
	}

	if client.Name != "Test Client" {
		t.Errorf("Expected name 'Test Client', got '%s'", client.Name)
	}

	if !client.Active {
		t.Error("Expected client to be active by default")
	}
}

func TestClientServiceGetClient(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	// Create a client first
	original, _ := service.CreateClient(t.Context(), "Get Test", "Desc", "http://localhost", []string{"read"})

	// Get the client
	retrieved, err := service.GetClient(t.Context(), original.ID)
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	if retrieved.ID != original.ID {
		t.Errorf("Expected ID '%s', got '%s'", original.ID, retrieved.ID)
	}

	if string(retrieved.Secret) != string(original.Secret) {
		t.Errorf("Expected secret '%s', got '%s'", string(original.Secret), string(retrieved.Secret))
	}
}

func TestClientServiceValidateClient(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	// Create a client
	client, _ := service.CreateClient(t.Context(), "Validate Test", "Desc", "http://localhost", []string{"read"})

	// Test valid credentials
	validated, err := service.ValidateClient(t.Context(), client.ID, client.GetSecretString())
	if err != nil {
		t.Fatalf("Failed to validate client: %v", err)
	}

	if validated.ID != client.ID {
		t.Error("Validated client ID doesn't match")
	}

	// Test invalid secret
	_, err = service.ValidateClient(t.Context(), client.ID, "wrong-secret")
	if err == nil {
		t.Error("Expected error for invalid secret")
	}

	// Test inactive client
	updates := map[string]any{
		"active": false,
	}
	if _, err := service.UpdateClient(t.Context(), client.ID, updates); err != nil {
		t.Fatalf("Failed to update client: %v", err)
	}

	_, err = service.ValidateClient(t.Context(), client.ID, client.GetSecretString())
	if err == nil {
		t.Error("Expected error for inactive client")
	}
}

func TestClientServiceUpdateClient(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	// Create a client
	client, _ := service.CreateClient(t.Context(), "Update Test", "Original Desc", "http://localhost", []string{"read"})

	// Update the client
	updates := map[string]any{
		"name":        "Updated Name",
		"description": "Updated Description",
		"scopes":      []string{"read", "write", "admin"},
	}

	updated, err := service.UpdateClient(t.Context(), client.ID, updates)
	if err != nil {
		t.Fatalf("Failed to update client: %v", err)
	}

	if updated.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", updated.Name)
	}

	if updated.Description != "Updated Description" {
		t.Errorf("Expected description 'Updated Description', got '%s'", updated.Description)
	}

	if len(updated.Scopes) != 3 {
		t.Errorf("Expected 3 scopes, got %d", len(updated.Scopes))
	}
}

func TestClientServiceDeleteClient(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	// Create a client
	client, _ := service.CreateClient(t.Context(), "Delete Test", "Desc", "http://localhost", []string{"read"})

	// Delete the client
	err := service.DeleteClient(client.ID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Try to get deleted client
	_, err = service.GetClient(t.Context(), client.ID)
	if err == nil {
		t.Error("Expected error when getting deleted client")
	}
}

func TestClientServiceListClients(t *testing.T) {
	t.Parallel()

	store, cleanup := createTestStore(t)
	t.Cleanup(cleanup)

	service := auth.NewClientService(store)

	// Create multiple clients
	for i := range 3 {
		if _, err := service.CreateClient(
			t.Context(),
			"List Test "+string(rune('A'+i)),
			"Desc",
			"http://localhost",
			[]string{"read"},
		); err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
	}

	// List clients
	clients, err := service.ListClients(t.Context())
	if err != nil {
		t.Fatalf("Failed to list clients: %v", err)
	}

	if len(clients) < 3 {
		t.Errorf("Expected at least 3 clients, got %d", len(clients))
	}
}

func TestTokenService(t *testing.T) {
	t.Parallel()

	t.Run("ProviderToken", func(t *testing.T) {
		t.Parallel()

		store, cleanup := createTestStore(t)
		t.Cleanup(cleanup)

		service := auth.NewTokenService(store)

		// Store provider token using the correct signature
		err := service.StoreProviderToken(t.Context(), "provider-access-token", "Bearer", "provider-refresh-token", 3600)
		if err != nil {
			t.Fatalf("Failed to store provider token: %v", err)
		}

		// Get provider token
		retrieved, err := service.GetProviderToken(t.Context())
		if err != nil {
			t.Fatalf("Failed to get provider token: %v", err)
		}

		if retrieved.AccessToken != "provider-access-token" {
			t.Errorf("Expected access token 'provider-access-token', got '%s'",
				retrieved.AccessToken)
		}
	})

	t.Run("NeedsProactiveRefresh", func(t *testing.T) {
		t.Parallel()

		store, cleanup := createTestStore(t)
		t.Cleanup(cleanup)

		service := auth.NewTokenService(store)

		// Test when no token exists
		needs := service.NeedsProactiveRefresh(t.Context())
		if !needs {
			t.Error("Should need refresh when no token exists")
		}

		// Store a token that expires in 1 day (less than 3 days)
		err := service.StoreProviderToken(t.Context(), "test-token", "Bearer", "refresh-token", 24*60*60)
		if err != nil {
			t.Fatalf("Failed to store token: %v", err)
		}

		needs = service.NeedsProactiveRefresh(t.Context())
		if !needs {
			t.Error("Should need refresh when token expires in 1 day")
		}

		// Store a token that expires in 5 days (more than 3 days)
		err = service.StoreProviderToken(t.Context(), "test-token", "Bearer", "refresh-token", 5*24*60*60)
		if err != nil {
			t.Fatalf("Failed to store token: %v", err)
		}

		needs = service.NeedsProactiveRefresh(t.Context())
		if needs {
			t.Error("Should not need refresh when token expires in 5 days")
		}
	})
}
