package health

// Config holds health check configuration options.
type Config struct {
	// Version to include in health responses
	Version string
}

// DefaultConfig returns health check configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: "schwab-proxy-1.0.0",
	}
}
