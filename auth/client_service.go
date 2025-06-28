package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jkoelker/schwab-proxy/storage"
)

// Sentinel errors for client service.
var (
	ErrClientInactive      = errors.New("client is inactive")
	ErrInvalidClientSecret = errors.New("invalid client secret")
)

// ClientService manages client applications.
type ClientService struct {
	store *storage.Store
}

// NewClientService creates a new client service.
func NewClientService(store *storage.Store) *ClientService {
	return &ClientService{
		store: store,
	}
}

// CreateClient registers a new client.
func (s *ClientService) CreateClient(
	ctx context.Context,
	name, description, redirectURI string,
	scopes []string,
) (*ClientWithSecret, error) {
	clientWithSecret, err := NewClientWithDetails(name, description, redirectURI, scopes)
	if err != nil {
		return nil, err
	}

	// Store only the client (with hashed secret) in the database
	key := storage.PrefixClient + clientWithSecret.ID
	if err := s.store.Set(ctx, key, clientWithSecret.Client, 0); err != nil {
		return nil, fmt.Errorf("failed to store client: %w", err)
	}

	// Return the client with plaintext secret for API response
	return clientWithSecret, nil
}

// GetClient retrieves a client by ID.
func (s *ClientService) GetClient(ctx context.Context, id string) (*Client, error) {
	var client Client

	key := storage.PrefixClient + id

	if err := s.store.Get(ctx, key, &client); err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return &client, nil
}

// ValidateClient checks if a client ID and secret are valid.
func (s *ClientService) ValidateClient(ctx context.Context, id, secret string) (*Client, error) {
	client, err := s.GetClient(ctx, id)
	if err != nil {
		return nil, err
	}

	if !client.Active {
		return nil, ErrClientInactive
	}

	if client.GetSecretString() != secret {
		return nil, ErrInvalidClientSecret
	}

	return client, nil
}

// UpdateClient updates a client's information.
func (s *ClientService) UpdateClient(ctx context.Context, clientID string, updates map[string]any) (*Client, error) {
	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	s.applyClientUpdates(client, updates)
	client.UpdatedAt = time.Now()

	key := storage.PrefixClient + clientID
	if err := s.store.Set(ctx, key, client, 0); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	return client, nil
}

// DeleteClient removes a client.
func (s *ClientService) DeleteClient(id string) error {
	key := storage.PrefixClient + id

	if err := s.store.Delete(key); err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	return nil
}

// ListClients returns all registered clients.
func (s *ClientService) ListClients(ctx context.Context) ([]*Client, error) {
	keys, err := s.store.List(storage.PrefixClient)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	clients := make([]*Client, 0, len(keys))

	for _, key := range keys {
		var client Client
		if err := s.store.Get(ctx, key, &client); err != nil {
			continue // Skip clients that can't be loaded
		}

		clients = append(clients, &client)
	}

	return clients, nil
}

// applyClientUpdates applies updates to a client object.
func (s *ClientService) applyClientUpdates(client *Client, updates map[string]any) {
	for key, value := range updates {
		s.applyIndividualUpdate(client, key, value)
	}
}

// applyIndividualUpdate applies a single update to a client field.
func (s *ClientService) applyIndividualUpdate(client *Client, key string, value any) {
	switch key {
	case "name":
		s.updateClientName(client, value)
	case "description":
		s.updateClientDescription(client, value)
	case "redirect_uri":
		s.updateClientRedirectURI(client, value)
	case "scopes":
		s.updateClientScopes(client, value)
	case "active":
		s.updateClientActive(client, value)
	}
}

// updateClientName updates the client name if value is a string.
func (s *ClientService) updateClientName(client *Client, value any) {
	if name, ok := value.(string); ok {
		client.Name = name
	}
}

// updateClientDescription updates the client description if value is a string.
func (s *ClientService) updateClientDescription(client *Client, value any) {
	if desc, ok := value.(string); ok {
		client.Description = desc
	}
}

// updateClientRedirectURI updates the client redirect URI if value is a string.
func (s *ClientService) updateClientRedirectURI(client *Client, value any) {
	if uri, ok := value.(string); ok {
		client.RedirectURIs = []string{uri}
	}
}

// updateClientScopes updates the client scopes if value is a string slice.
func (s *ClientService) updateClientScopes(client *Client, value any) {
	if scopes, ok := value.([]string); ok {
		client.Scopes = scopes
	}
}

// updateClientActive updates the client active status if value is a bool.
func (s *ClientService) updateClientActive(client *Client, value any) {
	if active, ok := value.(bool); ok {
		client.Active = active
	}
}
