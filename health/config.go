package health

// Config holds health check configuration options.
type Config struct {
	// StrictReadiness determines if degraded status should fail readiness checks
	// When true: degraded = 503 (Kubernetes-friendly, removes from load balancer)
	// When false: degraded = 200 (allows degraded pods to receive traffic)
	StrictReadiness bool

	// Version to include in health responses
	Version string
}

// DefaultConfig returns health check configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		StrictReadiness: true, // Default to Kubernetes-friendly behavior
		Version:         "schwab-proxy-1.0.0",
	}
}
