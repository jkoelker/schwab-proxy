package storage

import (
	"errors"
	"time"
)

// Prefixes for different data types.
const (
	// PrefixClient represents client-specific data.
	PrefixClient = "client:"

	// PrefixToken represents client tokens.
	PrefixToken = "token:"

	// PrefixOAuthToken represents OAuth provider tokens.
	PrefixOAuthToken = "oauth:"

	// PrefixAuthorization represents user authorizations.
	PrefixAuthorization = "auth:"

	// PrefixApprovalQueue represents pending authorization approvals.
	PrefixApprovalQueue = "approval:"
)

// Configuration constants.
const (
	// DefaultEncryptionKeyRotation is the default key rotation period.
	DefaultEncryptionKeyRotation = 24 * time.Hour

	// DefaultIndexCacheSize is the default index cache size in MB.
	DefaultIndexCacheSize = 100 << 20 // 100 MB

	// DefaultGCThreshold is the default garbage collection threshold.
	DefaultGCThreshold = 0.5

	// StorageSalt is the salt used for key derivation.
	StorageSalt = "schwab-proxy-storage-salt"

	// AES256KeySize is the key size for AES-256 encryption.
	AES256KeySize = 32
)

// Storage errors.
var (
	// ErrExpirationTooLarge is returned when the expiration timestamp exceeds
	// the maximum allowed value.
	ErrExpirationTooLarge = errors.New("expiration timestamp too large")

	// ErrInvalidValue is returned when a value cannot be marshaled or unmarshaled.
	ErrInvalidValue = errors.New("invalid value")
)

// Migration constants.
const (
	// KDFParamsFileName is the name of the external KDF parameters file.
	KDFParamsFileName = "kdf_params.json"

	// MigrationTempSuffix is appended to temporary directories during migration.
	MigrationTempSuffix = ".tmp"

	// DatabaseSubdir is the subdirectory name for the actual database files.
	// This allows migration operations to rename within the data directory.
	DatabaseSubdir = "db"

	// KDFParamsFileVersion is the current version of the KDF params file format.
	KDFParamsFileVersion = 1
)
