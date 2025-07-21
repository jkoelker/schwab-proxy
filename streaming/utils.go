package streaming

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrInvalidPrefixedRequestID is returned when a prefixed request ID has an invalid format.
var ErrInvalidPrefixedRequestID = errors.New("invalid prefixed request ID format")

// PrefixRequestID adds a client ID prefix to a request ID to prevent collisions
// and enable proper routing of responses.
// Format: "client_<uuid>_<original_request_id>".
func PrefixRequestID(clientID, requestID string) string {
	return fmt.Sprintf("%s_%s", clientID, requestID)
}

// UnprefixRequestID extracts the client ID and original request ID from a prefixed request ID.
// Returns an error if the format is invalid.
func UnprefixRequestID(prefixedID string) (string, string, error) {
	const expectedParts = 3

	parts := strings.SplitN(prefixedID, "_", expectedParts)

	if len(parts) != expectedParts || parts[0] != "client" {
		return "", "", fmt.Errorf("%w: %s", ErrInvalidPrefixedRequestID, prefixedID)
	}

	// Reconstruct the client ID
	clientID := "client_" + parts[1]
	requestID := parts[2]

	return clientID, requestID, nil
}

// IsPrefixedRequestID checks if a request ID has the expected client prefix format.
func IsPrefixedRequestID(requestID string) bool {
	const expectedParts = 3

	parts := strings.SplitN(requestID, "_", expectedParts)

	return len(parts) == expectedParts && parts[0] == "client"
}

// ClientMap provides a thread-safe map for managing WebSocket clients.
type ClientMap struct {
	m sync.Map
}

// NewClientMap creates a new ClientMap.
func NewClientMap() *ClientMap {
	return &ClientMap{}
}

// Store stores a client in the map.
func (cm *ClientMap) Store(id string, client *Client) {
	cm.m.Store(id, client)
}

// Load retrieves a client from the map.
func (cm *ClientMap) Load(id string) (*Client, bool) {
	val, ok := cm.m.Load(id)
	if !ok {
		return nil, false
	}

	if client, ok := val.(*Client); ok {
		return client, true
	}

	return nil, false
}

// Delete removes a client from the map.
func (cm *ClientMap) Delete(id string) {
	cm.m.Delete(id)
}

// Range calls f for each client in the map.
func (cm *ClientMap) Range(function func(id string, client *Client) bool) {
	cm.m.Range(func(key any, value any) bool {
		ident, ok := key.(string)
		if !ok {
			return true
		}

		client, ok := value.(*Client)
		if !ok {
			return true
		}

		return function(ident, client)
	})
}

// Count returns the number of clients in the map.
func (cm *ClientMap) Count() int {
	count := 0

	cm.m.Range(func(_ any, _ any) bool {
		count++

		return true
	})

	return count
}
