package storage_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/kdf"
	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/storage"
)

const testClient = "test-client"

//nolint:cyclop // This is a test file, cyclomatic complexity is not a concern here.
func TestMigration_LegacyToDefault(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-legacy-default")

	ctx := t.Context()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-12345")

	// Create test data with various key types
	testData := map[string]interface{}{
		"client:test-client": auth.Client{
			ID:     "test-client",
			Name:   "Test Client",
			Secret: []byte("test-secret"),
		},
		"access:test-access-token": map[string]interface{}{
			"client_id": "test-client",
			"scopes":    []string{"offline_access"},
			"session":   map[string]interface{}{"foo": "bar"},
		},
		"refresh:test-refresh": map[string]interface{}{
			"client_id":        "test-client",
			"scopes":           []string{"offline_access"},
			"access_signature": "test-access-token",
		},
		"oauth:current": map[string]interface{}{
			"access_token":  "provider-token",
			"refresh_token": "provider-refresh",
			"expires_in":    3600,
		},
		"auth:test-auth": map[string]string{
			"code":      "auth-code",
			"client_id": "test-client",
		},
	}

	// Create database with legacy params
	legacyParams := kdf.LegacyPBKDF2Params()
	if err := createTestDatabase(t, dbPath, seed, legacyParams, testData); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Perform migration to default params
	defaultParams := kdf.DefaultPBKDF2Params()

	store, err := storage.NewStoreWithMigration(ctx, dbPath, seed, defaultParams)
	if err != nil {
		t.Fatalf("Failed to migrate database: %v", err)
	}

	t.Cleanup(func() {
		// Ensure the store is closed after tests
		if err := store.Close(); err != nil {
			t.Errorf("Failed to close store: %v", err)
		}
	})

	// Verify all data was migrated correctly
	t.Run("VerifyClient", func(t *testing.T) {
		t.Parallel()

		var client auth.Client
		if err := store.Get(ctx, "client:test-client", &client); err != nil {
			t.Errorf("Failed to get migrated client: %v", err)
		}

		if client.ID != testClient || client.Name != "Test Client" {
			t.Errorf("Client data corrupted during migration")
		}
	})

	t.Run("VerifyAccessToken", func(t *testing.T) {
		t.Parallel()

		var tokenData map[string]interface{}
		if err := store.Get(ctx, "access:test-access-token", &tokenData); err != nil {
			t.Errorf("Failed to get migrated access token: %v", err)
		}

		if tokenData["client_id"] != testClient {
			t.Errorf("Access token data corrupted during migration")
		}
	})

	t.Run("VerifyRefreshToken", func(t *testing.T) {
		t.Parallel()

		var tokenData map[string]interface{}
		if err := store.Get(ctx, "refresh:test-refresh", &tokenData); err != nil {
			t.Errorf("Failed to get migrated refresh token: %v", err)
		}

		if tokenData["client_id"] != testClient {
			t.Errorf("Refresh token data corrupted during migration")
		}
	})

	t.Run("VerifyOAuthToken", func(t *testing.T) {
		t.Parallel()

		var oauthData map[string]interface{}
		if err := store.Get(ctx, "oauth:current", &oauthData); err != nil {
			t.Errorf("Failed to get migrated OAuth token: %v", err)
		}

		if oauthData["access_token"] != "provider-token" {
			t.Errorf("OAuth token data corrupted during migration")
		}
	})

	t.Run("VerifyKDFMetadata", func(t *testing.T) {
		t.Parallel()

		params, err := storage.GetCurrentKDFParams(dbPath)
		if err != nil {
			t.Errorf("Failed to get KDF params: %v", err)
		}

		if !params.Equal(defaultParams) {
			t.Errorf("KDF params not updated correctly")
		}
	})
}

//nolint:cyclop // This is a test file, cyclomatic complexity is not a concern here.
func TestMigration_WithTTL(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-ttl")

	ctx := t.Context()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-ttl")

	// Create database with legacy params and TTL data
	legacyParams := kdf.LegacyPBKDF2Params()

	// First create the store
	store1, err := createEmptyStore(t, dbPath, seed, legacyParams)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Add data with various TTLs
	ttl1Hour := 1 * time.Hour
	ttl24Hours := 24 * time.Hour

	testData := map[string]struct {
		value interface{}
		ttl   time.Duration
	}{
		"access:short-lived": {
			value: map[string]interface{}{
				"client_id": "test-client",
				"scopes":    []string{"offline_access"},
			},
			ttl: ttl1Hour,
		},
		"refresh:long-lived": {
			value: map[string]interface{}{
				"client_id": "test-client",
				"scopes":    []string{"offline_access"},
			},
			ttl: ttl24Hours,
		},
		"client:permanent": {
			value: auth.Client{
				ID:     "test-client",
				Name:   "Permanent Client",
				Secret: []byte("test-secret"),
			},
			ttl: 0, // No TTL
		},
	}

	// Store data with TTLs
	for key, data := range testData {
		if err := store1.Set(ctx, key, data.value, data.ttl); err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	// Get TTLs before migration
	ttlsBefore := make(map[string]time.Duration)

	for key := range testData {
		ttl, err := store1.TTL(key)
		if err != nil {
			t.Fatalf("Failed to get TTL for %s: %v", key, err)
		}

		ttlsBefore[key] = ttl
	}

	store1.Close()

	// Perform migration
	defaultParams := kdf.DefaultPBKDF2Params()

	store2, err := storage.NewStoreWithMigration(ctx, dbPath, seed, defaultParams)
	if err != nil {
		t.Fatalf("Failed to migrate database: %v", err)
	}

	t.Cleanup(func() {
		// Ensure the store is closed after tests
		if err := store2.Close(); err != nil {
			t.Errorf("Failed to close store after migration: %v", err)
		}
	})

	// Verify TTLs were preserved (with some tolerance for time passing)
	for key, expectedTTL := range ttlsBefore {
		actualTTL, err := store2.TTL(key)
		if err != nil {
			t.Errorf("Failed to get TTL for %s after migration: %v", key, err)

			continue
		}

		// Allow 1 minute tolerance for time passing during migration
		tolerance := 1 * time.Minute

		if expectedTTL == 0 {
			if actualTTL != 0 {
				t.Errorf("Key %s should have no TTL but has %v", key, actualTTL)
			}
		} else if actualTTL > expectedTTL || expectedTTL-actualTTL > tolerance {
			t.Errorf("TTL for %s not preserved: expected ~%v, got %v", key, expectedTTL, actualTTL)
		}

		// Verify data integrity
		var value interface{}

		switch key {
		case "access:short-lived", "refresh:long-lived":
			var tokenData map[string]interface{}
			if err := store2.Get(ctx, key, &tokenData); err != nil {
				t.Errorf("Failed to get %s after migration: %v", key, err)
			}

			value = tokenData

		case "client:permanent":
			var client auth.Client
			if err := store2.Get(ctx, key, &client); err != nil {
				t.Errorf("Failed to get %s after migration: %v", key, err)
			}

			value = client
		}

		if value == nil {
			t.Errorf("Data for %s lost during migration", key)
		}
	}
}

func TestMigration_CrossKDFTypes(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-cross-kdf")

	testCases := []struct {
		name    string
		fromKDF kdf.Params
		toKDF   kdf.Params
	}{
		{
			name:    "LegacyPBKDF2toDefault",
			fromKDF: kdf.LegacyPBKDF2Params(),
			toKDF:   kdf.DefaultPBKDF2Params(),
		},
		{
			name:    "PBKDF2toScrypt",
			fromKDF: kdf.DefaultPBKDF2Params(),
			toKDF:   kdf.DefaultScryptParams(),
		},
		{
			name:    "ScryptToPBKDF2",
			fromKDF: kdf.DefaultScryptParams(),
			toKDF:   kdf.DefaultPBKDF2Params(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			tempDir := t.TempDir()
			dbPath := filepath.Join(tempDir, "test.db")
			seed := []byte("test-seed-cross-kdf")

			// Create test data
			testData := map[string]interface{}{
				"test:key1": "value1",
				"test:key2": map[string]string{"nested": "value"},
				"test:key3": []string{"array", "of", "values"},
			}

			// Create database with source KDF
			if err := createTestDatabase(t, dbPath, seed, testCase.fromKDF, testData); err != nil {
				t.Fatalf("Failed to create database with %s: %v", testCase.fromKDF.Type(), err)
			}

			// Migrate to target KDF
			store, err := storage.NewStoreWithMigration(ctx, dbPath, seed, testCase.toKDF)
			if err != nil {
				t.Fatalf(
					"Failed to migrate from %s to %s: %v",
					testCase.fromKDF.Type(),
					testCase.toKDF.Type(),
					err,
				)
			}
			defer store.Close()

			// Verify all data migrated
			for key, expectedValue := range testData {
				var actualValue interface{}
				if err := store.Get(ctx, key, &actualValue); err != nil {
					t.Errorf("Failed to get %s after migration: %v", key, err)
				}

				// Compare JSON representations for complex types
				expectedJSON, _ := json.Marshal(expectedValue)
				actualJSON, _ := json.Marshal(actualValue)

				if string(expectedJSON) != string(actualJSON) {
					t.Errorf(
						"Data mismatch for %s: expected %s, got %s",
						key,
						expectedJSON,
						actualJSON,
					)
				}
			}

			// Verify KDF params updated
			params, err := storage.GetCurrentKDFParams(dbPath)
			if err != nil {
				t.Errorf("Failed to get KDF params: %v", err)
			}

			if !params.Equal(testCase.toKDF) {
				t.Errorf(
					"KDF params not updated: expected %s, got %s",
					testCase.toKDF.Type(),
					params.Type(),
				)
			}
		})
	}
}

//nolint:cyclop // This is a test file, cyclomatic complexity is not a concern here.
func TestMigration_LargeDataset(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-large")

	ctx := t.Context()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-large")

	// Create a large dataset
	numKeys := 1000
	testData := make(map[string]interface{})

	for idx := range numKeys {
		key := ""
		value := interface{}(nil)

		switch idx % 5 {
		case 0: // Clients
			key = "client:" + randomString(t, 16)
			value = auth.Client{
				ID:     randomString(t, 16),
				Name:   "Client " + randomString(t, 8),
				Secret: []byte(randomString(t, 32)),
			}
		case 1: // Access tokens
			key = "access:" + randomString(t, 32)
			value = map[string]interface{}{
				"client_id": "client-" + randomString(t, 8),
				"scopes":    []string{"offline_access"},
			}
		case 2: // Refresh tokens
			key = "refresh:" + randomString(t, 32)
			value = map[string]interface{}{
				"client_id":        "client-" + randomString(t, 8),
				"scopes":           []string{"offline_access"},
				"access_signature": randomString(t, 32),
			}
		case 3: // Auth codes
			key = "auth:" + randomString(t, 16)
			value = map[string]string{
				"code":      randomString(t, 32),
				"client_id": "client-" + randomString(t, 8),
			}
		case 4: // Generic data
			key = "data:" + randomString(t, 16)
			value = map[string]interface{}{
				"field1": randomString(t, 32),
				"field2": idx,
				"field3": time.Now().Unix(),
			}
		}

		testData[key] = value
	}

	// Create database with legacy params
	legacyParams := kdf.LegacyPBKDF2Params()
	if err := createTestDatabase(t, dbPath, seed, legacyParams, testData); err != nil {
		t.Fatalf("Failed to create large database: %v", err)
	}

	// Time the migration
	startTime := time.Now()

	// Perform migration
	defaultParams := kdf.DefaultPBKDF2Params()

	store, err := storage.NewStoreWithMigration(ctx, dbPath, seed, defaultParams)
	if err != nil {
		t.Fatalf("Failed to migrate large database: %v", err)
	}
	defer store.Close()

	migrationTime := time.Since(startTime)
	t.Logf("Migration of %d keys took %v", numKeys, migrationTime)

	// Verify a sample of keys
	verified := 0
	for key := range testData {
		if verified >= 100 { // Verify 100 random keys
			break
		}

		var actualValue interface{}
		if err := store.Get(ctx, key, &actualValue); err != nil {
			t.Errorf("Failed to get %s after migration: %v", key, err)

			continue
		}

		verified++
	}

	// Verify total key count
	allKeys := []string{}

	for prefix := range map[string]bool{
		"client:": true, "access:": true, "refresh:": true,
		"auth:": true, "data:": true,
	} {
		keys, err := store.List(prefix)
		if err != nil {
			t.Errorf("Failed to list keys with prefix %s: %v", prefix, err)

			continue
		}

		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) != numKeys {
		t.Errorf("Key count mismatch: expected %d, got %d", numKeys, len(allKeys))
	}
}

// Helper functions

// createTestKDFParams creates KDF params file and derives encryption key.
func createTestKDFParams(seed []byte, params kdf.Params) (*storage.KDFParamsFile, []byte, error) {
	// Create KDF params file first to get the salt
	paramsFile, err := storage.NewKDFParamsFile(params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create KDF params file: %w", err)
	}

	// Get the storage salt
	salt, err := paramsFile.GetSalt("storage")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get storage salt: %w", err)
	}

	encryptionKey, err := params.DeriveKey(seed, salt, storage.AES256KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return paramsFile, encryptionKey, nil
}

// openTestDatabase opens a BadgerDB instance with encryption.
func openTestDatabase(dbPath string, encryptionKey []byte) (*badger.DB, error) {
	// Create subdirectory
	actualDBPath := filepath.Join(dbPath, storage.DatabaseSubdir)
	if err := os.MkdirAll(actualDBPath, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	opts := badger.DefaultOptions(actualDBPath)
	opts = opts.WithEncryptionKey(encryptionKey)
	opts = opts.WithIndexCacheSize(storage.DefaultIndexCacheSize)
	opts = opts.WithLogger(nil)

	database, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open Badger database: %w", err)
	}

	return database, nil
}

// writeTestData writes test data to the database.
func writeTestData(database *badger.DB, testData map[string]interface{}) error {
	if err := database.Update(func(txn *badger.Txn) error {
		for key, value := range testData {
			data, err := json.Marshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
			}

			if err := txn.Set([]byte(key), data); err != nil {
				return fmt.Errorf("failed to set key %s: %w", key, err)
			}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}

	return nil
}

func createTestDatabase(
	t *testing.T,
	dbPath string,
	seed []byte,
	params kdf.Params,
	testData map[string]interface{},
) error {
	t.Helper()

	// Create KDF params and derive key
	paramsFile, encryptionKey, err := createTestKDFParams(seed, params)
	if err != nil {
		return err
	}

	// Open database
	database, err := openTestDatabase(dbPath, encryptionKey)
	if err != nil {
		return err
	}
	defer database.Close()

	// Store test data
	if err := writeTestData(database, testData); err != nil {
		return fmt.Errorf("failed to write test data: %w", err)
	}

	// Write KDF parameters to external file
	if err := paramsFile.WriteTo(dbPath); err != nil {
		return fmt.Errorf("failed to write KDF params file: %w", err)
	}

	return nil
}

func createEmptyStore(t *testing.T, dbPath string, seed []byte, params kdf.Params) (*storage.Store, error) {
	t.Helper()

	ctx := t.Context()

	store, err := storage.NewStoreWithMigration(ctx, dbPath, seed, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	return store, nil
}

func randomString(t *testing.T, length int) string {
	t.Helper()

	// Generate random bytes
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}

	// Encode to base64 and truncate to desired length
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
