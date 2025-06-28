package log_test

import (
	"testing"

	"github.com/jkoelker/schwab-proxy/log"
)

func TestIsSensitiveKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		// Sensitive keys that should be redacted
		{"password field", "password", true},
		{"user_password field", "user_password", true},
		{"secret field", "client_secret", true},
		{"token field", "access_token", true},
		{"auth field", "authorization", true},
		{"api_key field", "api_key", true},
		{"encryption_key field", "encryption_key", true},

		// Safe keys that should NOT be redacted (whitelisted)
		{"total_keys count", "total_keys", false},
		{"expired_keys count", "expired_keys", false},
		{"key_prefixes stats", "key_prefixes", false},
		{"migrated_keys count", "migrated_keys", false},
		{"error_keys count", "error_keys", false},
		{"keys count", "keys", false},

		// Regular fields that should not be redacted
		{"username field", "username", false},
		{"email field", "email", false},
		{"duration field", "duration", false},
		{"count field", "count", false},

		// Case insensitive checks
		{"uppercase PASSWORD", "PASSWORD", true},
		{"uppercase TOTAL_KEYS", "TOTAL_KEYS", false},
		{"mixed case Total_Keys", "Total_Keys", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := log.IsSensitiveKey(test.key)
			if result != test.expected {
				t.Errorf("isSensitiveKey(%q) = %v, want %v", test.key, result, test.expected)
			}
		})
	}
}
