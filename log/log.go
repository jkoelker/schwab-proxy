package log

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// loggerKey is the context key for storing the logger.
	loggerKey contextKey = "logger"
)

var (
	// defaultLogger is the fallback logger when none is found in context.
	defaultLogger *slog.Logger //nolint:gochecknoglobals // Thread-safe: protected by sync.Once

	// loggerOnce ensures we only initialize the default logger once.
	loggerOnce sync.Once //nolint:gochecknoglobals // Thread-safe: sync.Once is inherently safe

	// fallbackLogger is used when defaultLogger is nil and provides lazy initialization.
	fallbackLogger *slog.Logger //nolint:gochecknoglobals // Thread-safe: protected by sync.Once

	// fallbackOnce ensures we only create the fallback logger once.
	fallbackOnce sync.Once //nolint:gochecknoglobals // Thread-safe: sync.Once is inherently safe
)

// InitializeLogger sets up the global default logger.
func InitializeLogger(debugLogging bool) {
	loggerOnce.Do(func() {
		var level slog.Level
		if debugLogging {
			level = slog.LevelDebug
		} else {
			level = slog.LevelInfo
		}

		// Create slog handler with JSON output for structured logging
		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
				// Sanitize sensitive data
				if IsSensitiveKey(attr.Key) {
					return slog.Attr{Key: attr.Key, Value: slog.StringValue("[REDACTED]")}
				}

				return attr
			},
		})

		// Create slog logger
		defaultLogger = slog.New(handler)
	})
}

// WithLogger adds a logger to the context.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// WithValues returns a context with a logger that includes additional key-value pairs.
func WithValues(ctx context.Context, keysAndValues ...any) context.Context {
	logger := fromContext(ctx).With(keysAndValues...)

	return WithLogger(ctx, logger)
}

// WithName returns a context with a logger that includes an additional name component.
func WithName(ctx context.Context, name string) context.Context {
	logger := fromContext(ctx).WithGroup(name)

	return WithLogger(ctx, logger)
}

// fromContext retrieves the logger from context or returns default.
func fromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}

	if defaultLogger == nil {
		// Lazy initialization of fallback logger
		fallbackOnce.Do(func() {
			fallbackLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		})

		return fallbackLogger
	}

	return defaultLogger
}

// Info logs an info message with key-value pairs.
func Info(ctx context.Context, msg string, keysAndValues ...any) {
	fromContext(ctx).InfoContext(ctx, msg, keysAndValues...)
}

// Error logs an error message with key-value pairs.
func Error(ctx context.Context, err error, msg string, keysAndValues ...any) {
	allArgs := append([]any{"error", err}, keysAndValues...)
	fromContext(ctx).ErrorContext(ctx, msg, allArgs...)
}

// Debug logs a debug message with key-value pairs.
func Debug(ctx context.Context, msg string, keysAndValues ...any) {
	fromContext(ctx).DebugContext(ctx, msg, keysAndValues...)
}

// Warn logs a warning message with key-value pairs.
func Warn(ctx context.Context, msg string, keysAndValues ...any) {
	fromContext(ctx).WarnContext(ctx, msg, keysAndValues...)
}

// IsSensitiveKey checks if a log key contains sensitive information.
func IsSensitiveKey(key string) bool {
	// Whitelist certain keys that contain sensitive words but are safe to log
	safeKeys := []string{
		"total_keys",    // Count of keys, not actual keys
		"expired_keys",  // Count of expired keys
		"key_prefixes",  // Key type statistics
		"migrated_keys", // Migration statistics
		"error_keys",    // Error count
		"keys",          // Generic key count (used in migration logs)
	}

	keyLower := strings.ToLower(key)

	// Check if this is a whitelisted key
	for _, safe := range safeKeys {
		if keyLower == safe {
			return false
		}
	}

	sensitiveKeys := []string{
		"secret", "password", "token", "key", "auth", "credential",
		"bearer", "jwt", "oauth", "client_secret", "access_token",
		"refresh_token", "authorization", "api_key",
	}

	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}

	return false
}
