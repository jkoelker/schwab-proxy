package storage_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/jkoelker/schwab-proxy/kdf"
	"github.com/jkoelker/schwab-proxy/metrics"
	"github.com/jkoelker/schwab-proxy/storage"
)

const testValue = "test-value"

// setupStore creates a new store with encryption for testing and registers cleanup.
func setupStore(t *testing.T) *storage.Store {
	t.Helper()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-storage-test")

	// Create temp directory for test database
	tempDir := t.TempDir()

	// Create store with KDF migration support using default params
	seed := []byte("test-seed-for-storage-tests")
	params := kdf.DefaultPBKDF2Params()

	store, err := storage.NewStoreWithMigration(t.Context(), tempDir, seed, params)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Register cleanup function
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	})

	return store
}

// setupStoreWithPath creates a new store with encryption for testing and returns both store and path.
func setupStoreWithPath(t *testing.T) (*storage.Store, string) {
	t.Helper()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-storage-test")

	// Create temp directory for test database
	tempDir := t.TempDir()

	// Create store with KDF migration support using default params
	seed := []byte("test-seed-for-storage-tests")
	params := kdf.DefaultPBKDF2Params()

	store, err := storage.NewStoreWithMigration(t.Context(), tempDir, seed, params)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Register cleanup function
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	})

	return store, tempDir
}

// setupStoreWithoutEncryption creates a new store without encryption for testing and registers cleanup.
func setupStoreWithoutEncryption(t *testing.T) *storage.Store {
	t.Helper()

	// Initialize metrics for testing
	metrics.InitializeMeter("schwab-proxy-storage-test")

	// Create temp directory for test database
	tempDir := t.TempDir()

	// Create store without encryption
	store, err := storage.NewStore(tempDir, nil)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Register cleanup function
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Logf("Failed to close store: %v", err)
		}
	})

	return store
}

func TestStoreSetAndGet(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	type testData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	// Test data
	key := "test:key"
	expected := testData{
		Name:  "test",
		Value: 42,
	}

	// Set value
	if err := store.Set(t.Context(), key, expected, 0); err != nil {
		t.Fatalf("Failed to set value: %v", err)
	}

	// Get value
	var actual testData
	if err := store.Get(t.Context(), key, &actual); err != nil {
		t.Fatalf("Failed to get value: %v", err)
	}

	// Compare
	if actual.Name != expected.Name || actual.Value != expected.Value {
		t.Errorf("Expected %+v, got %+v", expected, actual)
	}
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	key := "test:delete"
	value := testValue

	// Set value
	if err := store.Set(t.Context(), key, value, 0); err != nil {
		t.Fatalf("Failed to set value: %v", err)
	}

	// Delete value
	if err := store.Delete(key); err != nil {
		t.Fatalf("Failed to delete value: %v", err)
	}

	// Try to get deleted value
	var result string

	err := store.Get(t.Context(), key, &result)
	if err == nil {
		t.Error("Expected error when getting deleted value")
	}
}

func TestStoreList(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	prefix := "list:test:"

	// Set multiple values
	for i := range 3 {
		key := prefix + string(rune('a'+i))
		if err := store.Set(t.Context(), key, i, 0); err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}
	}

	// List keys
	keys, err := store.List(prefix)
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
}

func TestStoreExpiration(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	key := "test:expire"
	value := testValue

	// Set value with longer expiration to ensure it exists when we check
	if err := store.Set(t.Context(), key, value, 2*time.Second); err != nil {
		t.Fatalf("Failed to set value: %v", err)
	}

	// Give BadgerDB time to commit the transaction (especially with encryption)
	time.Sleep(50 * time.Millisecond)

	// Value should exist immediately
	var result string
	if err := store.Get(t.Context(), key, &result); err != nil {
		t.Errorf("Value should exist immediately: %v", err)
	} else if result != value {
		t.Errorf("Expected '%s', got '%s'", value, result)
	}

	// Wait for expiration - wait longer than the TTL
	time.Sleep(3 * time.Second)

	// Value should be expired
	err := store.Get(t.Context(), key, &result)
	if err == nil {
		t.Error("Expected error when getting expired value")
	}
}

func TestStoreWithoutEncryption(t *testing.T) {
	t.Parallel()

	store := setupStoreWithoutEncryption(t)

	// Basic set/get test
	key := "test:noencrypt"
	value := testValue

	if err := store.Set(t.Context(), key, value, 0); err != nil {
		t.Fatalf("Failed to set value: %v", err)
	}

	var result string
	if err := store.Get(t.Context(), key, &result); err != nil {
		t.Fatalf("Failed to get value: %v", err)
	}

	if result != value {
		t.Errorf("Expected '%s', got '%s'", value, result)
	}
}

func TestStoreTTL(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	key := "ttl:test"
	value := "ttl-value"
	expectedTTL := 5 * time.Second

	// Set value with TTL
	if err := store.Set(t.Context(), key, value, expectedTTL); err != nil {
		t.Fatalf("Failed to set value with TTL: %v", err)
	}

	// Check TTL immediately
	ttl, err := store.TTL(key)
	if err != nil {
		t.Fatalf("Failed to get TTL: %v", err)
	}

	// TTL should be close to what we set (allow for small time passage)
	if ttl <= 0 || ttl > expectedTTL {
		t.Errorf("Invalid TTL: expected ~%v, got %v", expectedTTL, ttl)
	}

	// Set value without TTL
	noTTLKey := "nottl:test"
	if err := store.Set(t.Context(), noTTLKey, value, 0); err != nil {
		t.Fatalf("Failed to set value without TTL: %v", err)
	}

	// Check TTL for non-expiring key
	ttl2, err := store.TTL(noTTLKey)
	if err != nil {
		t.Fatalf("Failed to get TTL for non-expiring key: %v", err)
	}

	// Non-expiring keys should have negative TTL
	if ttl2 >= 0 {
		t.Errorf("Non-expiring key should have negative TTL, got %v", ttl2)
	}
}

func TestStoreTTL_NonExistentKey(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	_, err := store.TTL("nonexistent:key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	if !errors.Is(err, storage.ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestStoreRunGC(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	// Set multiple values with short TTL
	for i := range 10 {
		key := "gc:test:" + string(rune('a'+i))
		if err := store.Set(t.Context(), key, i, 1*time.Second); err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}
	}

	// Wait for values to expire
	time.Sleep(2 * time.Second)

	// Run garbage collection
	if err := store.RunGC(); err != nil {
		// GC might return an error if there's nothing to collect
		// which is OK for this test
		t.Logf("GC returned (possibly expected) error: %v", err)
	}

	// Verify values are gone
	for i := range 10 {
		key := "gc:test:" + string(rune('a'+i))

		var value int

		if err := store.Get(t.Context(), key, &value); err == nil {
			t.Errorf("Expected key %s to be garbage collected", key)
		}
	}
}

func TestStoreComplexDataTypes(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	type NestedStruct struct {
		ID        string            `json:"id"`
		Timestamp time.Time         `json:"timestamp"`
		Tags      []string          `json:"tags"`
		Metadata  map[string]string `json:"metadata"`
	}

	type ComplexData struct {
		Name     string         `json:"name"`
		Count    int            `json:"count"`
		Active   bool           `json:"active"`
		Nested   NestedStruct   `json:"nested"`
		Pointers *NestedStruct  `json:"pointers,omitempty"`
		Slice    []NestedStruct `json:"slice"`
	}

	now := time.Now().Round(time.Second) // Round to avoid nanosecond precision issues
	testData := ComplexData{
		Name:   "complex",
		Count:  42,
		Active: true,
		Nested: NestedStruct{
			ID:        "nested-1",
			Timestamp: now,
			Tags:      []string{"tag1", "tag2", "tag3"},
			Metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		Pointers: &NestedStruct{
			ID:        "pointer-1",
			Timestamp: now.Add(1 * time.Hour),
			Tags:      []string{"ptr-tag"},
			Metadata:  map[string]string{"ptr": "value"},
		},
		Slice: []NestedStruct{
			{
				ID:        "slice-1",
				Timestamp: now.Add(2 * time.Hour),
				Tags:      []string{"s1"},
				Metadata:  map[string]string{"s1": "v1"},
			},
			{
				ID:        "slice-2",
				Timestamp: now.Add(3 * time.Hour),
				Tags:      []string{"s2"},
				Metadata:  map[string]string{"s2": "v2"},
			},
		},
	}

	key := "complex:test"

	// Store complex data
	if err := store.Set(t.Context(), key, testData, 0); err != nil {
		t.Fatalf("Failed to set complex data: %v", err)
	}

	// Retrieve complex data
	var retrieved ComplexData
	if err := store.Get(t.Context(), key, &retrieved); err != nil {
		t.Fatalf("Failed to get complex data: %v", err)
	}

	// Verify all fields
	verifyComplexData(t, testData, retrieved)
}

func TestStoreListPrefixes(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	// Set up test data with different prefixes
	testData := map[string]string{
		"client:1":     "client1",
		"client:2":     "client2",
		"client:3":     "client3",
		"token:abc":    "token_abc",
		"token:def":    "token_def",
		"oauth:github": "oauth_github",
		"oauth:google": "oauth_google",
		"auth:user1":   "auth_user1",
		"other:data":   "other_data",
	}

	// Store all test data
	for key, value := range testData {
		if err := store.Set(t.Context(), key, value, 0); err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	// Test listing with different prefixes
	tests := []struct {
		prefix   string
		expected int
	}{
		{storage.PrefixClient, 3},
		{storage.PrefixToken, 2},
		{storage.PrefixOAuthToken, 2},
		{storage.PrefixAuthorization, 1},
		{"other:", 1},
		{"nonexistent:", 0},
	}

	for _, testCase := range tests {
		keys, err := store.List(testCase.prefix)
		if err != nil {
			t.Errorf("Failed to list keys with prefix %s: %v", testCase.prefix, err)

			continue
		}

		if len(keys) != testCase.expected {
			t.Errorf(
				"Prefix %s: expected %d keys, got %d",
				testCase.prefix,
				testCase.expected,
				len(keys),
			)
		}

		// Verify all returned keys have the correct prefix
		for _, key := range keys {
			if !strings.HasPrefix(key, testCase.prefix) {
				t.Errorf("Key %s does not have prefix %s", key, testCase.prefix)
			}
		}
	}
}

func TestStoreErrorCases(t *testing.T) {
	t.Parallel()

	store := setupStore(t)
	ctx := t.Context()

	t.Run("GetNonExistentKey", func(t *testing.T) {
		t.Parallel()

		var value string

		err := store.Get(ctx, "nonexistent:key", &value)
		if !errors.Is(err, storage.ErrKeyNotFound) {
			t.Errorf("Expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		t.Parallel()

		// Delete should not error on non-existent keys (idempotent)
		err := store.Delete("nonexistent:key")
		if err != nil {
			// BadgerDB doesn't error on deleting non-existent keys
			t.Logf("Delete returned error (may be OK): %v", err)
		}
	})

	t.Run("SetInvalidValue", func(t *testing.T) {
		t.Parallel()

		// Create a value that can't be marshaled to JSON
		type InvalidType struct {
			Ch chan int `json:"ch"`
		}

		invalid := InvalidType{Ch: make(chan int)}

		err := store.Set(ctx, "invalid:key", invalid, 0)
		if err == nil {
			t.Error("Expected error when setting unmarshallable value")
		}
	})

	t.Run("GetIntoWrongType", func(t *testing.T) {
		t.Parallel()

		// Set a string value
		if err := store.Set(ctx, "type:test", "string value", 0); err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}

		// Try to get it as an int
		var intValue int

		if err := store.Get(ctx, "type:test", &intValue); err == nil {
			t.Error("Expected error when unmarshaling into wrong type")
		}
	})
}

func TestStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-concurrent")

	store := setupStore(t)
	ctx := t.Context()

	// Run concurrent operations
	var waitGroup sync.WaitGroup

	errs := make(chan error, 100)

	// Writers
	for idx := range 10 {
		waitGroup.Add(1)

		go func(id int) {
			defer waitGroup.Done()

			for j := range 10 {
				key := "concurrent:test"
				value := id*100 + j

				if err := store.Set(ctx, key, value, 0); err != nil {
					errs <- err
				}
			}
		}(idx)
	}

	// Readers
	for range 10 {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			for range 10 {
				var value int

				_ = store.Get(ctx, "concurrent:test", &value)
			}
		}()
	}

	// Wait for all goroutines
	waitGroup.Wait()

	close(errs)

	// Check for errors
	for err := range errs {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

func TestStoreMetadata(t *testing.T) {
	t.Parallel()

	_, dbPath := setupStoreWithPath(t)

	// Initially, should return default params
	params, err := storage.GetCurrentKDFParams(dbPath)
	if err != nil {
		t.Fatalf("Failed to get initial KDF params: %v", err)
	}

	// Should be default PBKDF2 params
	if params.Type() != "pbkdf2" {
		t.Errorf("Expected pbkdf2, got %s", params.Type())
	}
}

// Migration tests

func TestNewStoreWithMigration_NewDatabase(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-12345")
	params := kdf.DefaultPBKDF2Params()

	// Create new database
	store, err := storage.NewStoreWithMigration(t.Context(), dbPath, seed, params)
	if err != nil {
		t.Fatalf("Failed to create new store: %v", err)
	}
	defer store.Close()

	// Verify metadata was stored
	metadata, err := storage.GetCurrentKDFParams(dbPath)
	if err != nil {
		t.Fatalf("Failed to get KDF params: %v", err)
	}

	if !metadata.Equal(params) {
		t.Errorf("Expected params %v, got %v", params, metadata)
	}
}

func TestNewStoreWithMigration_NoMigrationNeeded(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-no-migration")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-12345")
	params := kdf.DefaultPBKDF2Params()
	ctx := t.Context()

	// Create initial store
	store1, err := storage.NewStoreWithMigration(ctx, dbPath, seed, params)
	if err != nil {
		t.Fatalf("Failed to create initial store: %v", err)
	}

	// Store some data
	testKey := "test:data"
	testValue := map[string]string{"foo": "bar"}

	if err := store1.Set(ctx, testKey, testValue, 0); err != nil {
		t.Fatalf("Failed to set test data: %v", err)
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("Failed to close store1: %v", err)
	}

	// Reopen with same params - no migration should occur
	store2, err := storage.NewStoreWithMigration(ctx, dbPath, seed, params)
	if err != nil {
		t.Fatalf("Failed to reopen store: %v", err)
	}
	defer store2.Close()

	// Verify data is still there
	var retrieved map[string]string
	if err := store2.Get(ctx, testKey, &retrieved); err != nil {
		t.Fatalf("Failed to get test data: %v", err)
	}

	if retrieved["foo"] != testValue["foo"] {
		t.Errorf("Expected %v, got %v", testValue, retrieved)
	}
}

func TestNewStoreWithMigration_MigrationRequired(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-required")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-12345")

	// Create legacy database with test data
	legacyParams := kdf.LegacyPBKDF2Params()
	testData := map[string]any{
		"test:1":   "value1",
		"test:2":   "value2",
		"client:1": map[string]string{"name": "client1"},
	}

	if err := createLegacyDatabase(t, dbPath, seed, legacyParams, testData); err != nil {
		t.Fatalf("Failed to create legacy database: %v", err)
	}

	// Now open with new params - should trigger migration
	newParams := kdf.DefaultPBKDF2Params()
	ctx := t.Context()

	store, err := storage.NewStoreWithMigration(ctx, dbPath, seed, newParams)
	if err != nil {
		t.Fatalf("Failed to migrate store: %v", err)
	}
	defer store.Close()

	// Verify all data was migrated
	verifyMigratedData(t, store, testData)

	// Verify new params are stored
	currentParams, err := storage.GetCurrentKDFParams(dbPath)
	if err != nil {
		t.Fatalf("Failed to get current params: %v", err)
	}

	if !currentParams.Equal(newParams) {
		t.Errorf("Expected params %v, got %v", newParams, currentParams)
	}
}

func TestNewStoreWithMigration_MigrationWithTTL(t *testing.T) {
	t.Parallel()

	metrics.InitializeMeter("test-migration-ttl")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	seed := []byte("test-seed-12345")

	// Create initial store
	params := kdf.LegacyPBKDF2Params()

	ctx := t.Context()

	store1, err := storage.NewStoreWithMigration(ctx, dbPath, seed, params)
	if err != nil {
		t.Fatalf("Failed to create initial store: %v", err)
	}

	// Store data with TTL
	ttlKey := "ttl:test"
	ttlValue := "expires-soon"
	ttl := 10 * time.Minute

	if err := store1.Set(ctx, ttlKey, ttlValue, ttl); err != nil {
		t.Fatalf("Failed to set TTL data: %v", err)
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("Failed to close store1: %v", err)
	}

	// Migrate to new params
	newParams := kdf.DefaultPBKDF2Params()

	store2, err := storage.NewStoreWithMigration(ctx, dbPath, seed, newParams)
	if err != nil {
		t.Fatalf("Failed to migrate store: %v", err)
	}

	defer store2.Close()

	// Verify TTL data exists
	var retrieved string
	if err := store2.Get(ctx, ttlKey, &retrieved); err != nil {
		t.Fatalf("Failed to get TTL data: %v", err)
	}

	if retrieved != ttlValue {
		t.Errorf("Expected %s, got %s", ttlValue, retrieved)
	}

	// Verify TTL is preserved (should be less than original but > 0)
	remainingTTL, err := store2.TTL(ttlKey)
	if err != nil {
		t.Fatalf("Failed to get TTL: %v", err)
	}

	if remainingTTL <= 0 || remainingTTL > ttl {
		t.Errorf("Invalid TTL after migration: %v", remainingTTL)
	}
}

// verifyComplexData verifies all fields of ComplexData match expected values.
func verifyComplexData(t *testing.T, expected, actual any) {
	t.Helper()

	// Convert to JSON and back to handle the any types
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected: %v", err)
	}

	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("Failed to marshal actual: %v", err)
	}

	// Parse JSON to maps for field-by-field comparison
	var expectedMap, actualMap map[string]any
	if err := json.Unmarshal(expectedJSON, &expectedMap); err != nil {
		t.Fatalf("Failed to unmarshal expected: %v", err)
	}

	if err := json.Unmarshal(actualJSON, &actualMap); err != nil {
		t.Fatalf("Failed to unmarshal actual: %v", err)
	}

	// Compare basic fields
	if expectedMap["name"] != actualMap["name"] {
		t.Errorf("Name: expected %v, got %v", expectedMap["name"], actualMap["name"])
	}

	if expectedMap["count"] != actualMap["count"] {
		t.Errorf("Count: expected %v, got %v", expectedMap["count"], actualMap["count"])
	}

	if expectedMap["active"] != actualMap["active"] {
		t.Errorf("Active: expected %v, got %v", expectedMap["active"], actualMap["active"])
	}

	// For deep comparison, just check that the JSON representations match
	if string(expectedJSON) != string(actualJSON) {
		t.Errorf("Complex data mismatch:\nExpected: %s\nActual: %s", expectedJSON, actualJSON)
	}
}

// createLegacyKDFParams creates KDF params file and derives encryption key for legacy database.
func createLegacyKDFParams(seed []byte, params kdf.Params) (*storage.KDFParamsFile, []byte, error) {
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
		return nil, nil, fmt.Errorf("failed to derive legacy key: %w", err)
	}

	return paramsFile, encryptionKey, nil
}

// openLegacyDatabase opens a BadgerDB instance with encryption for legacy database.
func openLegacyDatabase(dbPath string, encryptionKey []byte) (*badger.DB, error) {
	// Create database directly with legacy key in subdirectory
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
		return nil, fmt.Errorf("failed to create legacy database: %w", err)
	}

	return database, nil
}

// writeLegacyData writes test data to the legacy database.
func writeLegacyData(database *badger.DB, testData map[string]any) error {
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

// createLegacyDatabase creates a database with legacy KDF params and test data.
func createLegacyDatabase(
	t *testing.T,
	dbPath string,
	seed []byte,
	legacyParams kdf.Params,
	testData map[string]any,
) error {
	t.Helper()

	// Create KDF params and derive key
	paramsFile, legacyKey, err := createLegacyKDFParams(seed, legacyParams)
	if err != nil {
		return err
	}

	// Open database
	database, err := openLegacyDatabase(dbPath, legacyKey)
	if err != nil {
		return err
	}
	defer database.Close()

	// Store test data
	if err := writeLegacyData(database, testData); err != nil {
		return fmt.Errorf("failed to write legacy data: %w", err)
	}

	// Write KDF parameters to external file
	if err := paramsFile.WriteTo(dbPath); err != nil {
		return fmt.Errorf("failed to write KDF params file: %w", err)
	}

	return nil
}

// verifyMigratedData verifies that all test data was properly migrated.
func verifyMigratedData(
	t *testing.T,
	store *storage.Store,
	testData map[string]any,
) {
	t.Helper()

	ctx := t.Context()

	for key, expectedValue := range testData {
		var actualValue any

		if err := store.Get(ctx, key, &actualValue); err != nil {
			t.Errorf("Failed to get migrated key %s: %v", key, err)

			continue
		}

		// Compare JSON representations for complex types
		expectedJSON, err := json.Marshal(expectedValue)
		if err != nil {
			t.Errorf("Failed to marshal expected value for key %s: %v", key, err)

			continue
		}

		actualJSON, err := json.Marshal(actualValue)
		if err != nil {
			t.Errorf("Failed to marshal actual value for key %s: %v", key, err)

			continue
		}

		if string(expectedJSON) != string(actualJSON) {
			t.Errorf("Key %s: expected %s, got %s", key, expectedJSON, actualJSON)
		}
	}
}
