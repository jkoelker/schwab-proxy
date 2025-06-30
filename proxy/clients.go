package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jkoelker/schwab-proxy/log"
)

// Client request/response structures.
type CreateClientRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
}

type UpdateClientRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	RedirectURI *string   `json:"redirect_uri,omitempty"`
	Scopes      *[]string `json:"scopes,omitempty"`
	Active      *bool     `json:"active,omitempty"`
}

type ClientResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	Active      bool     `json:"active"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type ClientWithSecretResponse struct {
	ClientResponse

	Secret string `json:"secret"`
}

// handleListClients returns all clients.
func (p *APIProxy) handleListClients(writer http.ResponseWriter, request *http.Request) {
	clients, err := p.clientService.ListClients(request.Context())
	if err != nil {
		log.Error(request.Context(), err, "failed to list clients")
		http.Error(writer, "Failed to list clients", http.StatusInternalServerError)

		return
	}

	// Convert to response format (without secrets)
	response := make([]ClientResponse, len(clients))
	for i, client := range clients {
		response[i] = ClientResponse{
			ID:          client.ID,
			Name:        client.Name,
			Description: client.Description,
			RedirectURI: getFirstRedirectURI(client.RedirectURIs),
			Scopes:      client.Scopes,
			Active:      client.Active,
			CreatedAt:   client.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   client.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)

		return
	}
}

// handleCreateClient creates a new client.
func (p *APIProxy) handleCreateClient(writer http.ResponseWriter, request *http.Request) {
	var req CreateClientRequest
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)

		return
	}

	// Validate required fields
	if req.Name == "" {
		http.Error(writer, "Client name is required", http.StatusBadRequest)

		return
	}

	if req.RedirectURI == "" {
		http.Error(writer, "Redirect URI is required", http.StatusBadRequest)

		return
	}

	// Create the client
	client, err := p.clientService.CreateClient(
		request.Context(),
		req.Name,
		req.Description,
		req.RedirectURI,
		req.Scopes,
	)
	if err != nil {
		log.Error(request.Context(), err, "failed to create client")
		http.Error(writer, "Failed to create client", http.StatusInternalServerError)

		return
	}

	// Return with secret (only time it's shown)
	response := ClientWithSecretResponse{
		ClientResponse: ClientResponse{
			ID:          client.ID,
			Name:        client.Name,
			Description: client.Description,
			RedirectURI: getFirstRedirectURI(client.RedirectURIs),
			Scopes:      client.Scopes,
			Active:      client.Active,
			CreatedAt:   client.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   client.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		Secret: client.PlaintextSecret, // Use the plaintext secret, not the hash
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)

		return
	}
}

// handleGetClient returns a specific client.
func (p *APIProxy) handleGetClient(writer http.ResponseWriter, request *http.Request) {
	// Extract client ID from path
	clientID := request.PathValue("id")
	if clientID == "" {
		http.Error(writer, "Client ID is required", http.StatusBadRequest)

		return
	}

	client, err := p.clientService.GetClient(request.Context(), clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(writer, "Client not found", http.StatusNotFound)
		} else {
			log.Error(request.Context(), err, "failed to get client")
			http.Error(writer, "Failed to get client", http.StatusInternalServerError)
		}

		return
	}

	response := ClientResponse{
		ID:          client.ID,
		Name:        client.Name,
		Description: client.Description,
		RedirectURI: getFirstRedirectURI(client.RedirectURIs),
		Scopes:      client.Scopes,
		Active:      client.Active,
		CreatedAt:   client.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   client.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)

		return
	}
}

// buildUpdateMap builds the update map from request fields.
func buildUpdateMap(req UpdateClientRequest) map[string]any {
	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}

	if req.Description != nil {
		updates["description"] = *req.Description
	}

	if req.RedirectURI != nil {
		updates["redirect_uri"] = *req.RedirectURI
	}

	if req.Scopes != nil {
		updates["scopes"] = *req.Scopes
	}

	if req.Active != nil {
		updates["active"] = *req.Active
	}

	return updates
}

// handleUpdateClientError handles error responses for client updates.
func handleUpdateClientError(ctx context.Context, writer http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "not found") {
		http.Error(writer, "Client not found", http.StatusNotFound)
	} else {
		log.Error(ctx, err, "failed to update client")
		http.Error(writer, "Failed to update client", http.StatusInternalServerError)
	}
}

// handleUpdateClient updates a client.
func (p *APIProxy) handleUpdateClient(writer http.ResponseWriter, request *http.Request) {
	// Extract client ID from path
	clientID := request.PathValue("id")
	if clientID == "" {
		http.Error(writer, "Client ID is required", http.StatusBadRequest)

		return
	}

	var req UpdateClientRequest
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)

		return
	}

	// Build update map
	updates := buildUpdateMap(req)
	if len(updates) == 0 {
		http.Error(writer, "No fields to update", http.StatusBadRequest)

		return
	}

	ctx := request.Context()

	client, err := p.clientService.UpdateClient(ctx, clientID, updates)
	if err != nil {
		handleUpdateClientError(ctx, writer, err)

		return
	}

	response := ClientResponse{
		ID:          client.ID,
		Name:        client.Name,
		Description: client.Description,
		RedirectURI: getFirstRedirectURI(client.RedirectURIs),
		Scopes:      client.Scopes,
		Active:      client.Active,
		CreatedAt:   client.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   client.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)

		return
	}
}

// handleDeleteClient deletes a client.
func (p *APIProxy) handleDeleteClient(writer http.ResponseWriter, request *http.Request) {
	// Extract client ID from path
	clientID := request.PathValue("id")
	if clientID == "" {
		http.Error(writer, "Client ID is required", http.StatusBadRequest)

		return
	}

	if err := p.clientService.DeleteClient(clientID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(writer, "Client not found", http.StatusNotFound)
		} else {
			log.Error(request.Context(), err, "failed to delete client")
			http.Error(writer, "Failed to delete client", http.StatusInternalServerError)
		}

		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

// getFirstRedirectURI returns the first redirect URI or empty string if none.
func getFirstRedirectURI(redirectURIs []string) string {
	if len(redirectURIs) > 0 {
		return redirectURIs[0]
	}

	return ""
}

// withAPIAuth middleware ensures request has valid API authentication
// For now, this is a simple bearer token check, but could be expanded.
func (p *APIProxy) withAPIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// For MVP, we'll use a simple API key from environment
		// In production, this should be a proper authentication system
		authHeader := request.Header.Get("Authorization")
		expectedKey := p.cfg.AdminAPIKey

		if expectedKey == "" {
			// If no admin key is set, deny access
			http.Error(writer, "Admin API not configured", http.StatusForbidden)

			return
		}

		if authHeader != "Bearer "+expectedKey {
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)

			return
		}

		next(writer, request)
	}
}
