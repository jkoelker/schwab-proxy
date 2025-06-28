package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/jkoelker/schwab-proxy/kdf"
	"github.com/jkoelker/schwab-proxy/log"
)

var (
	// ErrUnsupportedKDFParamsVersion indicates that the KDF parameters file
	// version is not supported.
	ErrUnsupportedKDFParamsVersion = errors.New("unsupported KDF params version")

	// ErrTTLOverflow indicates that the TTL calculation would result in integer overflow.
	ErrTTLOverflow = errors.New("TTL calculation would overflow")

	// ErrKDFParamsMissingSalts indicates that the KDF parameters file is missing required salts.
	ErrKDFParamsMissingSalts = errors.New("KDF params file missing salts")

	// ErrSaltNotFound indicates that a requested salt was not found in the KDF parameters.
	ErrSaltNotFound = errors.New("salt not found")
)

const (
	// dirPermissions is the permission mode for created directories.
	dirPermissions = 0o700
	// kdfParamsFilePermissions is the permission mode for KDF params file.
	kdfParamsFilePermissions = 0o600
	// saltLength is the length of generated salts in bytes.
	saltLength = 32 // 256 bits
)

// KDFParamsFile represents the external KDF parameters file.
type KDFParamsFile struct {
	Version   int               `json:"version"`    // File format version
	Type      string            `json:"type"`       // KDF type ("pbkdf2", "scrypt", "argon2id")
	Params    json.RawMessage   `json:"params"`     // The actual KDF parameters (marshaled with type info)
	Salts     map[string]string `json:"salts"`      // Base64-encoded salts for different purposes
	CreatedAt time.Time         `json:"created_at"` // When this configuration was created
}

// NewKDFParamsFile creates a new KDF parameters file with the given params.
func NewKDFParamsFile(params kdf.Params) (*KDFParamsFile, error) {
	// Marshal the params to get the wrapped format
	wrapped, err := kdf.MarshalParams(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KDF params: %w", err)
	}

	// Unwrap to get just the params content
	var wrapper struct {
		Type   string          `json:"type"`
		Params json.RawMessage `json:"params"`
	}

	if err := json.Unmarshal(wrapped, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unwrap KDF params: %w", err)
	}

	// Generate cryptographically secure salts
	salts, err := generateSalts()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salts: %w", err)
	}

	return &KDFParamsFile{
		Version:   KDFParamsFileVersion,
		Type:      string(params.Type()),
		Params:    wrapper.Params, // Just the inner params, not the wrapped version
		Salts:     salts,
		CreatedAt: time.Now(),
	}, nil
}

// generateSalts generates cryptographically secure random salts for storage and JWT.
func generateSalts() (map[string]string, error) {
	// Generate storage salt
	storageSalt := make([]byte, saltLength)
	if _, err := rand.Read(storageSalt); err != nil {
		return nil, fmt.Errorf("failed to generate storage salt: %w", err)
	}

	// Generate JWT salt
	jwtSalt := make([]byte, saltLength)
	if _, err := rand.Read(jwtSalt); err != nil {
		return nil, fmt.Errorf("failed to generate JWT salt: %w", err)
	}

	return map[string]string{
		"storage": base64.StdEncoding.EncodeToString(storageSalt),
		"jwt":     base64.StdEncoding.EncodeToString(jwtSalt),
	}, nil
}

// GetParams unmarshals and returns the KDF parameters.
func (k *KDFParamsFile) GetParams() (kdf.Params, error) {
	// Wrap the params with type information for UnmarshalParams
	wrapper := struct {
		Type   string          `json:"type"`
		Params json.RawMessage `json:"params"`
	}{
		Type:   k.Type,
		Params: k.Params,
	}

	wrappedData, err := json.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap KDF params: %w", err)
	}

	// Use the existing KDF unmarshaling logic
	params, err := kdf.UnmarshalParams(wrappedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDF params: %w", err)
	}

	return params, nil
}

// GetSalt returns the decoded salt for the given key.
func (k *KDFParamsFile) GetSalt(key string) ([]byte, error) {
	saltStr, ok := k.Salts[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSaltNotFound, key)
	}

	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s salt: %w", key, err)
	}

	return salt, nil
}

// WriteTo writes the KDF parameters to the external file in the database directory.
func (k *KDFParamsFile) WriteTo(dbPath string) error {
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal KDF params: %w", err)
	}

	actualDBPath := filepath.Join(dbPath, DatabaseSubdir)
	paramsPath := filepath.Join(actualDBPath, KDFParamsFileName)

	// Ensure the directory exists
	if err := os.MkdirAll(actualDBPath, dirPermissions); err != nil {
		return fmt.Errorf("failed to create directory for KDF params: %w", err)
	}

	if err := os.WriteFile(paramsPath, data, kdfParamsFilePermissions); err != nil {
		return fmt.Errorf("failed to write KDF params file: %w", err)
	}

	return nil
}

// MigrationStats tracks migration progress.
type MigrationStats struct {
	TotalKeys    int
	MigratedKeys int
	ErrorKeys    int
	StartTime    time.Time
	EndTime      time.Time
}

// MigrationItem represents a key-value pair with TTL for migration.
type MigrationItem struct {
	Key   []byte
	Value []byte
	TTL   time.Duration
}

// deriveOldKey derives the encryption key for the existing database.
func deriveOldKey(
	dbPath string,
	oldParams kdf.Params,
	seed []byte,
) ([]byte, error) {
	// Read the existing KDF params file to get the old salt
	oldParamsFile, err := readKDFParamsFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read old KDF params file: %w", err)
	}

	oldSalt, err := oldParamsFile.GetSalt("storage")
	if err != nil {
		return nil, fmt.Errorf("failed to get old storage salt: %w", err)
	}

	oldKey, err := oldParams.DeriveKey(seed, oldSalt, AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive old key: %w", err)
	}

	return oldKey, nil
}

// deriveNewKey derives the encryption key with a newly generated salt.
func deriveNewKey(
	newParams kdf.Params,
	newSalt []byte,
	seed []byte,
) ([]byte, error) {
	newKey, err := newParams.DeriveKey(seed, newSalt, AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive new key: %w", err)
	}

	return newKey, nil
}

// logExportStats logs statistics about exported data.
func logExportStats(ctx context.Context, items []MigrationItem) {
	keyPrefixCounts := make(map[string]int)
	expiredCount := 0

	for _, item := range items {
		keyStr := string(item.Key)
		if idx := strings.Index(keyStr, ":"); idx > 0 {
			prefix := keyStr[:idx+1]
			keyPrefixCounts[prefix]++
		}

		if item.TTL > 0 && item.TTL <= 60*time.Second {
			expiredCount++
		}
	}

	log.Info(ctx, "Exported data from old database",
		"total_keys", len(items),
		"expired_keys", expiredCount,
		"key_prefixes", keyPrefixCounts)
}

// createBackup creates a backup of the database directory.
func createBackup(ctx context.Context, dbPath, actualDBPath string) (string, error) {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	backupName := "db-" + timestamp
	backupPath := filepath.Join(dbPath, backupName)

	if err := os.Rename(actualDBPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	log.Info(ctx, "Created backup", "path", backupPath)

	return backupPath, nil
}

// createNewParamsAndKey creates new KDF params file and derives the new key.
func createNewParamsAndKey(newParams kdf.Params, seed []byte) (*KDFParamsFile, []byte, error) {
	// Create new params file with new salt to get the new key
	newParamsFile, err := NewKDFParamsFile(newParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new KDF params file: %w", err)
	}

	// Get the new storage salt
	newSalt, err := newParamsFile.GetSalt("storage")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get new storage salt: %w", err)
	}

	// Derive the new key with the new salt
	newKey, err := deriveNewKey(newParams, newSalt, seed)
	if err != nil {
		return nil, nil, err
	}

	return newParamsFile, newKey, nil
}

// performMigration migrates the database to use new KDF parameters.
// Since BadgerDB handles encryption at the storage layer, we need to:
// 1. Export all data from the old database.
// 2. Create a backup by renaming the db subdirectory.
// 3. Create a new database with the new encryption key.
// 4. Import all data.
// 5. Write the new KDF params file.
func performMigration(
	ctx context.Context,
	dbPath string,
	oldParams,
	newParams kdf.Params,
	seed []byte,
) (*MigrationStats, error) {
	stats := &MigrationStats{
		StartTime: time.Now(),
	}

	log.Info(ctx, "Starting KDF migration",
		"old_type", oldParams.Type(),
		"new_type", newParams.Type())

	// Derive the old key using the existing salt
	oldKey, err := deriveOldKey(dbPath, oldParams, seed)
	if err != nil {
		return nil, err
	}

	// Create new params and derive key
	newParamsFile, newKey, err := createNewParamsAndKey(newParams, seed)
	if err != nil {
		return nil, err
	}

	// Clear keys when done
	defer func() {
		for i := range oldKey {
			oldKey[i] = 0
		}

		for i := range newKey {
			newKey[i] = 0
		}
	}()

	// Use the actual database subdirectory
	actualDBPath := filepath.Join(dbPath, DatabaseSubdir)
	// Step 1: Export all data from old database
	items, err := exportDatabase(actualDBPath, oldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to export database: %w", err)
	}

	stats.TotalKeys = len(items)

	// Log key summary for debugging
	logExportStats(ctx, items)

	// Step 2: Create backup by renaming the subdirectory with timestamp
	backupPath, err := createBackup(ctx, dbPath, actualDBPath)
	if err != nil {
		return nil, err
	}

	// Step 3: Create new database directly in the final location
	if err := importDatabase(actualDBPath, newKey, items); err != nil {
		// Restore backup on error
		_ = os.RemoveAll(actualDBPath)
		_ = os.Rename(backupPath, actualDBPath)

		return nil, fmt.Errorf("failed to import to new database: %w", err)
	}

	stats.MigratedKeys = len(items)

	// Step 4: Write the new KDF params file with new salts
	if err := newParamsFile.WriteTo(dbPath); err != nil {
		// Restore backup on error
		_ = os.RemoveAll(actualDBPath)
		_ = os.Rename(backupPath, actualDBPath)

		return nil, fmt.Errorf("failed to write new KDF params file: %w", err)
	}

	// Step 5: Keep backup for potential rollback
	log.Info(ctx, "Backup preserved for rollback", "path", backupPath)

	stats.EndTime = time.Now()
	duration := stats.EndTime.Sub(stats.StartTime)

	log.Info(ctx, "KDF migration completed",
		"duration", duration,
		"migrated", stats.MigratedKeys,
		"errors", stats.ErrorKeys,
		"backup", backupPath)

	return stats, nil
}

// calculateRemainingTTL calculates the remaining TTL for a BadgerDB item,
// returning an error if the calculation would result in integer overflow.
func calculateRemainingTTL(expiresAt uint64) (time.Duration, error) {
	if expiresAt == 0 {
		return 0, nil
	}

	now := time.Now().Unix()

	// Check if now is negative (shouldn't happen in practice, but be defensive)
	if now < 0 {
		return 0, ErrTTLOverflow
	}

	nowUint := uint64(now)

	// Check if the key has already expired
	if nowUint >= expiresAt {
		// Return 1 second TTL for expired items so they expire immediately
		// rather than becoming permanent (TTL=0 means no expiration)
		return 1 * time.Second, nil
	}

	// Calculate remaining seconds
	remainingSeconds := expiresAt - nowUint

	// Check if converting to time.Duration would overflow
	// time.Duration is int64 in nanoseconds, so max seconds is roughly 2^63 / 1e9
	const maxDurationSeconds = uint64(math.MaxInt64 / int64(time.Second))
	if remainingSeconds > maxDurationSeconds {
		return 0, ErrTTLOverflow
	}

	return time.Duration(remainingSeconds) * time.Second, nil
}

// exportDatabase exports all key-value pairs from a BadgerDB database.
func exportDatabase(dbPath string, encryptionKey []byte) ([]MigrationItem, error) {
	opts := badger.DefaultOptions(dbPath)
	if len(encryptionKey) > 0 {
		opts = opts.WithEncryptionKey(encryptionKey)
		opts = opts.WithIndexCacheSize(DefaultIndexCacheSize)
	}

	opts = opts.WithLogger(nil)
	opts = opts.WithReadOnly(true)

	database, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database for export: %w", err)
	}
	defer database.Close()

	var items []MigrationItem

	if err := database.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// We skip expired keys during migration
		opts.AllVersions = false
		opts.InternalAccess = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			// Skip deleted or expired keys
			if item.IsDeletedOrExpired() {
				continue
			}

			key := item.KeyCopy(nil)

			var value []byte

			value, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("failed to copy value for key %s: %w", key, err)
			}

			// Calculate TTL for non-expired keys
			ttl, err := calculateRemainingTTL(item.ExpiresAt())
			if err != nil {
				return fmt.Errorf("failed to calculate TTL for key %s: %w", key, err)
			}

			items = append(items, MigrationItem{
				Key:   key,
				Value: value,
				TTL:   ttl,
			})
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate database: %w", err)
	}

	return items, nil
}

// createDatabaseOptions creates BadgerDB options with encryption if provided.
func createDatabaseOptions(dbPath string, encryptionKey []byte) badger.Options {
	opts := badger.DefaultOptions(dbPath)
	if len(encryptionKey) > 0 {
		opts = opts.WithEncryptionKey(encryptionKey)
		opts = opts.WithIndexCacheSize(DefaultIndexCacheSize)
	}

	opts = opts.WithLogger(nil)
	opts = opts.WithSyncWrites(false)

	return opts
}

// importItems imports all items into the database.
func importItems(database *badger.DB, items []MigrationItem) error {
	if err := database.Update(func(txn *badger.Txn) error {
		for _, item := range items {
			entry := badger.NewEntry(item.Key, item.Value)
			if item.TTL > 0 {
				entry = entry.WithTTL(item.TTL)
			}

			if err := txn.SetEntry(entry); err != nil {
				return fmt.Errorf("failed to set key %s: %w", item.Key, err)
			}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}

	return nil
}

// importDatabase imports key-value pairs into a new BadgerDB database.
func importDatabase(
	dbPath string,
	encryptionKey []byte,
	items []MigrationItem,
) error {
	// Ensure directory exists
	if err := os.MkdirAll(dbPath, dirPermissions); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	opts := createDatabaseOptions(dbPath, encryptionKey)

	database, err := badger.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open database for import: %w", err)
	}
	defer database.Close()

	// Import all items
	if err := importItems(database, items); err != nil {
		return fmt.Errorf("failed to import items: %w", err)
	}

	return nil
}

// readKDFParamsFile reads the KDF parameters from an external file.
func readKDFParamsFile(dbPath string) (*KDFParamsFile, error) {
	actualDBPath := filepath.Join(dbPath, DatabaseSubdir)
	paramsPath := filepath.Join(actualDBPath, KDFParamsFileName)

	data, err := os.ReadFile(paramsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("KDF params file not found: %w", err)
		}

		return nil, fmt.Errorf("failed to read KDF params file: %w", err)
	}

	var paramsFile KDFParamsFile
	if err := json.Unmarshal(data, &paramsFile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDF params file: %w", err)
	}

	// Validate file version
	if paramsFile.Version != KDFParamsFileVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedKDFParamsVersion, paramsFile.Version)
	}

	// Validate salts are present
	if len(paramsFile.Salts) == 0 {
		return nil, ErrKDFParamsMissingSalts
	}

	if _, ok := paramsFile.Salts["storage"]; !ok {
		return nil, fmt.Errorf("%w: missing storage salt", ErrKDFParamsMissingSalts)
	}

	if _, ok := paramsFile.Salts["jwt"]; !ok {
		return nil, fmt.Errorf("%w: missing jwt salt", ErrKDFParamsMissingSalts)
	}

	// Validate that params can be unmarshaled
	if _, err := paramsFile.GetParams(); err != nil {
		return nil, fmt.Errorf("invalid KDF params: %w", err)
	}

	return &paramsFile, nil
}

// GetCurrentKDFParams retrieves the current KDF parameters from external file.
func GetCurrentKDFParams(dbPath string) (kdf.Params, error) {
	paramsFile, err := readKDFParamsFile(dbPath)
	if err != nil {
		return nil, err
	}

	return paramsFile.GetParams()
}

// ReadKDFParamsFile reads and returns the KDF parameters file.
func ReadKDFParamsFile(dbPath string) (*KDFParamsFile, error) {
	return readKDFParamsFile(dbPath)
}
