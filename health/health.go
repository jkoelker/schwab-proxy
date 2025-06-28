package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jkoelker/schwab-proxy/api"
	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/storage"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"

	// providerAPICheckerName is the name for the provider API health checker.
	providerAPICheckerName = "provider_api"

	// storageTestTimeout is the timeout for storage health check operations.
	storageTestTimeout = 5 * time.Second
)

// Check represents a single health check.
type Check struct {
	Name        string            `json:"name"`
	Status      Status            `json:"status"`
	Message     string            `json:"message,omitempty"`
	Error       string            `json:"error,omitempty"`
	LastChecked time.Time         `json:"last_checked"`
	Duration    time.Duration     `json:"duration_ms"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Response represents the overall health response.
type Response struct {
	Status  Status           `json:"status"`
	Version string           `json:"version,omitempty"`
	Checks  map[string]Check `json:"checks"`
	Summary map[string]int   `json:"summary"`
}

// Checker defines the interface for health checks.
type Checker interface {
	Check(ctx context.Context) Check
	Name() string
}

// Manager manages and executes health checks.
type Manager struct {
	checkers []Checker
	config   *Config
}

// NewManager creates a new health checker.
func NewManager(version string) *Manager {
	config := DefaultConfig()
	config.Version = version

	return &Manager{
		checkers: make([]Checker, 0),
		config:   config,
	}
}

// NewManagerWithConfig creates a new health checker with custom config.
func NewManagerWithConfig(config *Config) *Manager {
	return &Manager{
		checkers: make([]Checker, 0),
		config:   config,
	}
}

// AddChecker adds a health checker.
func (hc *Manager) AddChecker(checker Checker) {
	hc.checkers = append(hc.checkers, checker)
}

// CheckLiveness performs basic liveness checks (server is running).
func (hc *Manager) CheckLiveness(_ context.Context) Response {
	// Liveness is simple - if we can respond, we're alive
	return Response{
		Status:  StatusHealthy,
		Version: hc.config.Version,
		Checks: map[string]Check{
			"server": {
				Name:        "server",
				Status:      StatusHealthy,
				Message:     "Server is responding",
				LastChecked: time.Now(),
				Duration:    0,
			},
		},
		Summary: map[string]int{
			"healthy":   1,
			"unhealthy": 0,
			"degraded":  0,
		},
	}
}

// CheckReadiness performs comprehensive readiness checks (dependencies).
func (hc *Manager) CheckReadiness(ctx context.Context) Response {
	checks := make(map[string]Check)
	summary := map[string]int{
		"healthy":   0,
		"unhealthy": 0,
		"degraded":  0,
	}

	// Execute all registered checkers
	for _, checker := range hc.checkers {
		start := time.Now()
		check := checker.Check(ctx)
		check.Duration = time.Since(start)
		checks[check.Name] = check

		// Update summary
		switch check.Status {
		case StatusHealthy:
			summary["healthy"]++
		case StatusUnhealthy:
			summary["unhealthy"]++
		case StatusDegraded:
			summary["degraded"]++
		}
	}

	// Determine overall status
	overallStatus := StatusHealthy
	if summary["unhealthy"] > 0 {
		overallStatus = StatusUnhealthy
	} else if summary["degraded"] > 0 {
		overallStatus = StatusDegraded
	}

	return Response{
		Status:  overallStatus,
		Version: hc.config.Version,
		Checks:  checks,
		Summary: summary,
	}
}

// StorageChecker checks BadgerDB connectivity.
type StorageChecker struct {
	store *storage.Store
}

// NewStorageChecker creates a new storage health checker.
func NewStorageChecker(store *storage.Store) *StorageChecker {
	return &StorageChecker{store: store}
}

// Name returns the checker name.
func (sc *StorageChecker) Name() string {
	return "storage"
}

// Check performs the storage health check.
func (sc *StorageChecker) Check(ctx context.Context) Check {
	check := Check{
		Name:        "storage",
		LastChecked: time.Now(),
		Metadata:    make(map[string]string),
	}

	// Test basic storage operations
	testKey := "health:check:" + time.Now().Format("20060102150405")
	testValue := "health-check-value"

	// Try to write
	if err := sc.store.Set(ctx, testKey, testValue, storageTestTimeout); err != nil {
		check.Status = StatusUnhealthy
		check.Error = "Failed to write to storage: " + err.Error()

		return check
	}

	// Try to read
	var retrievedValue string
	if err := sc.store.Get(ctx, testKey, &retrievedValue); err != nil {
		check.Status = StatusUnhealthy
		check.Error = "Failed to read from storage: " + err.Error()

		return check
	}

	// Verify value
	if retrievedValue != testValue {
		check.Status = StatusUnhealthy
		check.Error = "Storage returned incorrect value"

		return check
	}

	// Clean up
	if err := sc.store.Delete(testKey); err != nil {
		log.Warn(ctx, "Failed to clean up health check key", "key", testKey, "error", err.Error())
	}

	check.Status = StatusHealthy
	check.Message = "Storage is accessible and functioning"

	return check
}

// ProviderChecker checks Schwab API connectivity.
type ProviderChecker struct {
	client api.ProviderClient
}

// NewProviderChecker creates a new provider health checker.
func NewProviderChecker(client api.ProviderClient) *ProviderChecker {
	return &ProviderChecker{client: client}
}

// Name returns the checker name.
func (pc *ProviderChecker) Name() string {
	return providerAPICheckerName
}

// Check performs the provider API health check.
func (pc *ProviderChecker) Check(_ context.Context) Check {
	check := Check{
		Name:        providerAPICheckerName,
		LastChecked: time.Now(),
		Metadata:    make(map[string]string),
	}

	// Check if we have a valid token
	token, err := pc.client.GetToken()
	if err != nil {
		check.Status = StatusDegraded
		check.Message = "No provider token available - setup required"
		check.Metadata["setup_required"] = "true"

		return check
	}

	if !token.Valid() {
		check.Status = StatusDegraded
		check.Message = "Provider token expired - will refresh on next request"
		check.Metadata["token_expired"] = "true"

		return check
	}

	// For now, just check token validity
	// In a full implementation, we might make a lightweight API call
	check.Status = StatusHealthy
	check.Message = "Provider token is valid"
	check.Metadata["token_expires_at"] = token.Expiry.Format(time.RFC3339)

	return check
}

// HTTPHandler creates HTTP handlers for health endpoints.
type HTTPHandler struct {
	checker *Manager
}

// NewHTTPHandler creates a new HTTP handler for health checks.
func NewHTTPHandler(checker *Manager) *HTTPHandler {
	return &HTTPHandler{checker: checker}
}

// LivenessHandler handles liveness probe requests.
func (h *HTTPHandler) LivenessHandler(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	log.Debug(ctx, "Liveness check requested")

	response := h.checker.CheckLiveness(ctx)

	// Always return 200 for liveness unless the server is completely broken
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Error(ctx, err, "Failed to encode liveness response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	log.Debug(ctx, "Liveness check completed", "status", string(response.Status))
}

// ReadinessHandler handles readiness probe requests.
func (h *HTTPHandler) ReadinessHandler(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	log.Debug(ctx, "Readiness check requested")

	response := h.checker.CheckReadiness(ctx)

	// Return appropriate HTTP status based on health
	// For Kubernetes: Only return 200 if completely healthy
	// This ensures degraded pods are removed from load balancer rotation
	var statusCode int

	switch response.Status {
	case StatusHealthy:
		statusCode = http.StatusOK
	case StatusDegraded:
		// Check configuration for how to handle degraded status
		if h.checker.config.StrictReadiness {
			// Return 503 for degraded to remove from K8s service endpoints
			// This is more conservative but safer for production
			statusCode = http.StatusServiceUnavailable
		} else {
			// Allow degraded pods to continue receiving traffic
			statusCode = http.StatusOK
		}
	case StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	default:
		statusCode = http.StatusServiceUnavailable
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Error(ctx, err, "Failed to encode readiness response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	log.Debug(ctx, "Readiness check completed",
		"status", string(response.Status),
		"status_code", statusCode,
		"healthy_checks", response.Summary["healthy"],
		"unhealthy_checks", response.Summary["unhealthy"],
		"degraded_checks", response.Summary["degraded"],
	)
}
