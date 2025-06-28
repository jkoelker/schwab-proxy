package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/jkoelker/schwab-proxy/kdf"
)

// Cryptographic constants.
const (
	keySize  = 32    // 256-bit key size for AES-256 and JWT
	dirMode  = 0o755 // Directory creation mode
	fileMode = 0o600 // File creation mode (user read/write only)
)

// Schwab API constants.
const (
	// SchwabAuthURL is the URL for Schwab OAuth authorization.
	SchwabAuthURL = "https://api.schwabapi.com/v1/oauth/authorize"

	// SchwabTokenURL is the URL for Schwab OAuth token exchange.
	SchwabTokenURL = "https://api.schwabapi.com/v1/oauth/token" //nolint:gosec // Just a URL

	// SchwabAPIBase is the base URL for Schwab API endpoints.
	SchwabAPIBase = "https://api.schwabapi.com"
)

// Config holds the application configuration.
type Config struct {
	// Server configuration
	ListenAddr string `env:"LISTEN_ADDR" envDefault:"127.0.0.1"`
	Port       int    `env:"PORT"        envDefault:"8080"`

	// Seed values for key derivation (required and sensitive)
	StorageSeed string `env:"STORAGE_SEED,required"`
	JWTSeed     string `env:"JWT_SEED,required"`

	// Master Schwab connection settings (required)
	SchwabClientID     string `env:"SCHWAB_CLIENT_ID,required"`
	SchwabClientSecret string `env:"SCHWAB_CLIENT_SECRET,required"`
	SchwabRedirectURI  string `env:"SCHWAB_REDIRECT_URI,required"`

	// Data storage settings
	DataPath string `env:"DATA_PATH" envDefault:"./data"`

	// OAuth2 token settings
	OAuth2AccessTokenExpiry  time.Duration `env:"OAUTH2_ACCESS_TOKEN_EXPIRY"  envDefault:"12h"`
	OAuth2RefreshTokenExpiry time.Duration `env:"OAUTH2_REFRESH_TOKEN_EXPIRY" envDefault:"168h"`
	OAuth2AuthCodeExpiry     time.Duration `env:"OAUTH2_AUTH_CODE_EXPIRY"     envDefault:"10m"`

	// Debug options
	DebugLogging               bool `env:"DEBUG_LOGGING"                  envDefault:"false"`
	SendDebugMessagesToClients bool `env:"SEND_DEBUG_MESSAGES_TO_CLIENTS" envDefault:"false"`

	// Admin API settings (generated, not from env)
	AdminAPIKey string `env:"-"`

	// Observability settings
	ServiceName    string `env:"SERVICE_NAME"    envDefault:"schwab-proxy"`
	MetricsEnabled bool   `env:"METRICS_ENABLED" envDefault:"true"`
	TracingEnabled bool   `env:"TRACING_ENABLED" envDefault:"true"`

	// TLS settings
	TLSCertPath string `env:"TLS_CERT_PATH"`
	TLSKeyPath  string `env:"TLS_KEY_PATH"`

	// OAuth2 authorization settings
	AutoApproveAuthorization bool `env:"AUTO_APPROVE_AUTHORIZATION" envDefault:"true"`

	// Cryptographic settings
	// KDF specification (e.g., "pbkdf2:default", "argon2:high", "scrypt:moderate")
	KDFSpec string `env:"KDF_SPEC" envDefault:"argon2:default"`
}

// GetStorageKDFParams returns the KDF parameters for storage encryption.
func (c *Config) GetStorageKDFParams() (kdf.Params, error) {
	params, err := kdf.ParseSpec(c.KDFSpec)
	if err != nil {
		return nil, fmt.Errorf("invalid KDF spec %q: %w", c.KDFSpec, err)
	}

	return params, nil
}

// GetJWTKDFParams returns the KDF parameters for JWT signing.
// Currently always returns default PBKDF2 params.
func (c *Config) GetJWTKDFParams() (kdf.Params, error) {
	// For now, JWT always uses default PBKDF2
	// This could be extended with a separate JWT_KDF_SPEC env var if needed
	return kdf.DefaultPBKDF2Params(), nil
}

// generateSecureKey generates a cryptographically secure random key.
func generateSecureKey() (string, error) {
	bytes := make([]byte, keySize) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure key: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// getOrCreateAdminKey gets the admin API key from env or generates/loads
// from file.
func getOrCreateAdminKey(dataPath string) (string, error) {
	// First check environment variable
	if key := os.Getenv("ADMIN_API_KEY"); key != "" {
		return key, nil
	}

	// Check for existing key file
	// Clean the path to prevent directory traversal
	cleanDataPath := filepath.Clean(dataPath)
	keyPath := filepath.Join(cleanDataPath, "admin_api_key")

	// Try to read existing key file
	if keyBytes, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(keyBytes))
		if key != "" {
			slog.Info("Loaded existing admin API key", "admin_key_path", keyPath)

			return key, nil
		}
	}

	// Generate new key
	key, err := generateSecureKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate admin API key: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(cleanDataPath, dirMode); err != nil {
		return "", fmt.Errorf("failed to create data directory: %w", err)
	}

	// Write key to file with restricted permissions
	if err := os.WriteFile(keyPath, []byte(key), fileMode); err != nil {
		return "", fmt.Errorf("failed to write admin API key to %s: %w", keyPath, err)
	}

	slog.Info("Generated new admin API key",
		"key_path", keyPath,
		"note", "Keep this key secure and use it for admin API calls")

	return key, nil
}

// Load creates a Config from environment variables.
func Load() (*Config, error) {
	config := &Config{}

	// Parse environment variables using struct tags
	if err := env.Parse(config); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	// Clear sensitive environment variables for security
	clearEnvVar("STORAGE_SEED")
	clearEnvVar("JWT_SEED")
	clearEnvVar("SCHWAB_CLIENT_SECRET")

	// Get or create admin API key
	adminKey, err := getOrCreateAdminKey(config.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin API key: %w", err)
	}

	config.AdminAPIKey = adminKey

	return config, nil
}

// clearEnvVar removes the specified environment variable to prevent it from
// being exposed in process listings.
func clearEnvVar(key string) {
	_ = os.Unsetenv(key)
}
