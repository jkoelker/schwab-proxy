package streaming

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jkoelker/schwab-proxy/api"
)

var ErrNoMetadata = errors.New("no metadata available")

const defaultMetadataTTL = 24 * time.Hour

// UserPreferencesResponse represents the user preferences API response.
type UserPreferencesResponse struct {
	//nolint:tagliatelle // Schwab API response structure
	StreamerInfo []StreamerInfo `json:"streamerInfo"`
}

// StreamerInfo contains streaming configuration.
type StreamerInfo struct {
	//nolint:tagliatelle // Schwab API response structure
	StreamerSocketURL string `json:"streamerSocketUrl"`

	//nolint:tagliatelle // Schwab API response structure
	SchwabClientCustomerID string `json:"schwabClientCustomerId"`

	//nolint:tagliatelle // Schwab API response structure
	SchwabClientCorrelID string `json:"schwabClientCorrelId"`

	//nolint:tagliatelle // Schwab API response structure
	SchwabClientChannel string `json:"schwabClientChannel"`

	//nolint:tagliatelle // Schwab API response structure
	SchwabClientFunctionID string `json:"schwabClientFunctionId"`
}

// MetadataManager manages streaming metadata with caching.
type MetadataManager struct {
	metadata    *Metadata
	mu          sync.RWMutex
	refreshFunc func() (*Metadata, error)
	lastRefresh time.Time
}

// NewMetadataManager creates a metadata manager.
func NewMetadataManager(refreshFunc func() (*Metadata, error)) *MetadataManager {
	return &MetadataManager{
		refreshFunc: refreshFunc,
	}
}

// GetMetadata returns current metadata, refreshing if needed.
func (m *MetadataManager) GetMetadata() (*Metadata, error) {
	m.mu.RLock()

	if m.metadata != nil && time.Since(m.lastRefresh) < m.metadata.TTL {
		metadata := m.metadata
		m.mu.RUnlock()

		return metadata, nil
	}

	m.mu.RUnlock()

	// Need to refresh
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if m.metadata != nil && time.Since(m.lastRefresh) < m.metadata.TTL {
		return m.metadata, nil
	}

	// Refresh metadata
	metadata, err := m.refreshFunc()
	if err != nil {
		return nil, err
	}

	m.metadata = metadata
	m.lastRefresh = time.Now()

	return metadata, nil
}

// CreateMetadataFunc creates a metadata refresh function.
func CreateMetadataFunc(ctx context.Context, schwabClient api.ProviderClient) func() (*Metadata, error) {
	return func() (*Metadata, error) {
		resp, err := schwabClient.Call(ctx, "GET", "/trader/v1/userPreference", nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user preferences: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)

			return nil, fmt.Errorf(
				"%w: preferences request failed: %d - %s",
				ErrNoMetadata,
				resp.StatusCode,
				string(body),
			)
		}

		var prefs UserPreferencesResponse
		if err := json.NewDecoder(resp.Body).Decode(&prefs); err != nil {
			return nil, fmt.Errorf("failed to decode user preferences: %w", err)
		}

		if len(prefs.StreamerInfo) == 0 {
			return nil, fmt.Errorf("%w: no streaming info in response", ErrNoMetadata)
		}

		metadata := &Metadata{
			CorrelID:    prefs.StreamerInfo[0].SchwabClientCorrelID,
			CustomerID:  prefs.StreamerInfo[0].SchwabClientCustomerID,
			Channel:     prefs.StreamerInfo[0].SchwabClientChannel,
			FunctionID:  prefs.StreamerInfo[0].SchwabClientFunctionID,
			WSEndpoint:  prefs.StreamerInfo[0].StreamerSocketURL,
			ExtractedAt: time.Now(),
			TTL:         defaultMetadataTTL,
		}

		return metadata, nil
	}
}
