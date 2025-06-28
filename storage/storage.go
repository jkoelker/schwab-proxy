package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"

	"github.com/jkoelker/schwab-proxy/kdf"
	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/metrics"
)

// ErrKeyNotFound is an alias for BadgerDB's key not found error.
var ErrKeyNotFound = badger.ErrKeyNotFound

// Store represents the data storage layer.
type Store struct {
	db *badger.DB
}

// NewStore initializes a new storage with the given options.
func NewStore(dbPath string, encryptionKey []byte) (*Store, error) {
	// Use subdirectory for database files
	actualDBPath := filepath.Join(dbPath, DatabaseSubdir)
	// Ensure the directory exists
	if err := os.MkdirAll(actualDBPath, dirPermissions); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Configure BadgerDB
	opts := badger.DefaultOptions(actualDBPath)

	// Enable encryption if a key is provided
	if len(encryptionKey) > 0 {
		opts = opts.WithEncryptionKey(encryptionKey)
		opts = opts.WithEncryptionKeyRotationDuration(DefaultEncryptionKeyRotation)
		opts = opts.WithIndexCacheSize(DefaultIndexCacheSize)
	}

	// Configure for better performance in a proxy setting
	opts = opts.WithSyncWrites(false)
	opts = opts.WithLogger(nil) // Disable default logger
	opts = opts.WithCompression(options.Snappy)

	// Open the database
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &Store{db: db}, nil
}

// NewStoreWithMigration initializes storage with KDF migration support.
func NewStoreWithMigration(
	ctx context.Context,
	dbPath string,
	seed []byte,
	newParams kdf.Params,
) (*Store, error) {
	// Check if the actual database subdirectory exists
	actualDBPath := filepath.Join(dbPath, DatabaseSubdir)
	dbExists := false

	// Check for MANIFEST file to confirm it's a BadgerDB
	if _, err := os.Stat(filepath.Join(actualDBPath, "MANIFEST")); err == nil {
		dbExists = true
	}

	// If database doesn't exist, create it with new params
	if !dbExists {
		return createNewDatabase(ctx, dbPath, seed, newParams)
	}

	// Database exists - check if migration is needed
	return handleExistingDatabase(ctx, dbPath, seed, newParams)
}

// createNewDatabase creates a new database with the specified KDF params.
func createNewDatabase(ctx context.Context, dbPath string, seed []byte, newParams kdf.Params) (*Store, error) {
	log.Info(ctx, "Creating new database with KDF params", "params", formatKDFParams(newParams))

	// Create KDF params file with generated salts
	paramsFile, err := NewKDFParamsFile(newParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create KDF params file: %w", err)
	}

	// Get the storage salt
	salt, err := paramsFile.GetSalt("storage")
	if err != nil {
		return nil, fmt.Errorf("failed to get storage salt: %w", err)
	}

	encryptionKey, err := newParams.DeriveKey(seed, salt, AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	store, err := NewStore(dbPath, encryptionKey)
	if err != nil {
		return nil, err
	}

	// Write KDF parameters to external file
	if err := paramsFile.WriteTo(dbPath); err != nil {
		_ = store.Close()

		return nil, fmt.Errorf("failed to write KDF params file: %w", err)
	}

	return store, nil
}

// handleExistingDatabase handles an existing database, performing migration if needed.
func handleExistingDatabase(
	ctx context.Context,
	dbPath string,
	seed []byte,
	newParams kdf.Params,
) (*Store, error) {
	tempStore, currentParams, err := openStoreForMigrationCheck(dbPath, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to check migration status: %w", err)
	}

	// Close the temporary store
	_ = tempStore.Close()

	// Check if migration is needed
	if currentParams.Equal(newParams) {
		log.Info(ctx, "No migration needed, KDF params unchanged")

		return openStoreWithParams(dbPath, seed, newParams)
	}

	// Migration needed
	return performMigrationAndOpen(ctx, dbPath, seed, currentParams, newParams)
}

// openStoreWithParams opens a store with the given KDF params.
func openStoreWithParams(dbPath string, seed []byte, params kdf.Params) (*Store, error) {
	// Read the KDF params file to get the salt
	paramsFile, err := readKDFParamsFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KDF params file: %w", err)
	}

	// Get the storage salt
	salt, err := paramsFile.GetSalt("storage")
	if err != nil {
		return nil, fmt.Errorf("failed to get storage salt: %w", err)
	}

	encryptionKey, err := params.DeriveKey(seed, salt, AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return NewStore(dbPath, encryptionKey)
}

// performMigrationAndOpen performs the migration and opens the store.
func performMigrationAndOpen(
	ctx context.Context,
	dbPath string,
	seed []byte,
	currentParams, newParams kdf.Params,
) (*Store, error) {
	log.Info(ctx, "KDF migration required",
		"from", formatKDFParams(currentParams),
		"to", formatKDFParams(newParams))

	// Perform migration
	stats, err := performMigration(ctx, dbPath, currentParams, newParams, seed)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	log.Info(ctx, "Migration completed successfully",
		"keys", stats.MigratedKeys,
		"duration", stats.EndTime.Sub(stats.StartTime))

	// Open the migrated database
	return openStoreWithParams(dbPath, seed, newParams)
}

// openStoreForMigrationCheck opens the store to check current KDF params.
func openStoreForMigrationCheck(dbPath string, seed []byte) (*Store, kdf.Params, error) {
	// Try to read KDF params from external file first
	paramsFile, err := readKDFParamsFile(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read KDF params file: %w", err)
	}

	// Get the actual KDF params
	params, err := paramsFile.GetParams()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get KDF params: %w", err)
	}

	// Get the storage salt
	salt, err := paramsFile.GetSalt("storage")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get storage salt: %w", err)
	}

	// Derive encryption key using the params from file
	encryptionKey, err := params.DeriveKey(seed, salt, AES256KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Open store with derived key
	store, err := NewStore(dbPath, encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open database: %w", err)
	}

	return store, params, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	return nil
}

// Set stores a value with the given key.
func (s *Store) Set(ctx context.Context, key string, value any, expiry time.Duration) error {
	start := time.Now()

	// Record storage metrics
	defer func() {
		duration := time.Since(start)

		metrics.RecordCounter(
			ctx, "storage_operations_total", 1,
			"operation", "set",
		)
		metrics.RecordHistogram(
			ctx, "storage_operation_duration_ms", float64(duration.Milliseconds()),
			"operation", "set",
		)
	}()

	// Convert value to JSON
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	if err := s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(key), data)
		if expiry > 0 {
			entry = entry.WithTTL(expiry)
		}

		return txn.SetEntry(entry)
	}); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}

	return nil
}

// Get retrieves a value by key and unmarshals it into the provided struct.
func (s *Store) Get(ctx context.Context, key string, value any) error {
	start := time.Now()

	// Record storage metrics
	defer func() {
		duration := time.Since(start)

		metrics.RecordCounter(
			ctx, "storage_operations_total", 1,
			"operation", "get",
		)
		metrics.RecordHistogram(
			ctx, "storage_operation_duration_ms", float64(duration.Milliseconds()),
			"operation", "get",
		)
	}()

	var data []byte

	if err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to get key %s: %w", key, err)
		}

		data, err = item.ValueCopy(nil)
		if err != nil {
			return fmt.Errorf("failed to copy value for key %s: %w", key, err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to retrieve key %s: %w", key, err)
	}

	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("failed to unmarshal value for key %s: %w", key, err)
	}

	return nil
}

// Delete removes a key from the database.
func (s *Store) Delete(key string) error {
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	}); err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}

	return nil
}

// List returns all keys with the given prefix.
func (s *Store) List(prefix string) ([]string, error) {
	var keys []string

	if err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // Keys only

		it := txn.NewIterator(opts)
		defer it.Close()

		prefixBytes := []byte(prefix)
		for it.Seek(prefixBytes); it.ValidForPrefix(prefixBytes); it.Next() {
			item := it.Item()
			key := string(item.Key())
			keys = append(keys, key)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to list keys with prefix %s: %w", prefix, err)
	}

	return keys, nil
}

// TTL returns the time-to-live for a key.
func (s *Store) TTL(key string) (time.Duration, error) {
	var ttl time.Duration

	if err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to get key %s: %w", key, err)
		}

		// Safe conversion with overflow check
		expires := item.ExpiresAt()
		if expires > math.MaxInt64 {
			return ErrExpirationTooLarge
		}

		expiresAt := time.Unix(int64(expires), 0)
		ttl = time.Until(expiresAt)

		return nil
	}); err != nil {
		return 0, fmt.Errorf("failed to get TTL for key %s: %w", key, err)
	}

	return ttl, nil
}

// RunGC runs garbage collection to clean up expired keys.
func (s *Store) RunGC() error {
	if err := s.db.RunValueLogGC(DefaultGCThreshold); err != nil {
		return fmt.Errorf("failed to run garbage collection: %w", err)
	}

	return nil
}

// formatKDFParams formats KDF parameters for logging.
func formatKDFParams(params kdf.Params) string {
	switch typed := params.(type) {
	case *kdf.PBKDF2Params:
		hash := typed.HashFunc

		if hash == "" {
			hash = "sha256" // default
		}

		return fmt.Sprintf("pbkdf2(iterations=%d,hash=%s)", typed.Iterations, hash)

	case *kdf.Argon2idParams:
		return fmt.Sprintf(
			"argon2id(iterations=%d,memory=%dKB,parallelism=%d)",
			typed.Iterations,
			typed.Memory,
			typed.Parallelism,
		)

	case *kdf.ScryptParams:
		return fmt.Sprintf(
			"scrypt(cost=%d,block_size=%d,parallelism=%d)",
			typed.Cost,
			typed.BlockSize,
			typed.Parallelism,
		)

	default:
		return fmt.Sprintf("%s(unknown)", params.Type())
	}
}
