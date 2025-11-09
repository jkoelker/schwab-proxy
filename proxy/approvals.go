package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/storage"
)

const tenMinuteExpiry = 10 * time.Minute

// ApprovalListItem represents a minimal approval item in the list response.
type ApprovalListItem struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	CreatedAt string `json:"created_at"`
}

// handleListApprovals returns all pending approval requests.
func (p *APIProxy) handleListApprovals(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	approvals, err := p.storage.ListPendingApprovals(ctx)
	if err != nil {
		log.Error(ctx, err, "failed to list approvals")
		http.Error(writer, "Failed to list approvals", http.StatusInternalServerError)

		return
	}

	// Convert to minimal response format
	items := make([]ApprovalListItem, 0, len(approvals))
	for _, approval := range approvals {
		items = append(items, ApprovalListItem{
			ID:        approval.ID,
			ClientID:  approval.ClientID,
			CreatedAt: approval.CreatedAt.Format(time.RFC3339),
		})
	}

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(items); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)
	}
}

// handleApproveRequest approves a pending authorization request.
func (p *APIProxy) handleApproveRequest(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	approvalID := request.PathValue("id")

	// Get the approval request
	approval, err := p.storage.GetApprovalRequest(ctx, approvalID)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			http.Error(writer, "Approval request not found", http.StatusNotFound)

			return
		}

		log.Error(ctx, err, "failed to get approval request")
		http.Error(writer, "Failed to get approval", http.StatusInternalServerError)

		return
	}

	// Get the client via the auth server storage
	client, err := p.server.Storage().GetClient(ctx, approval.ClientID)
	if err != nil {
		http.Error(writer, "Client not found", http.StatusNotFound)

		return
	}

	fositeReq := &fosite.AuthorizeRequest{
		ResponseTypes: []string{"code"},
		Request: fosite.Request{
			ID:             approval.ID,
			RequestedAt:    approval.CreatedAt,
			Client:         client,
			RequestedScope: approval.Scopes,
			GrantedScope:   approval.Scopes,
			Form:           make(url.Values),
		},
		State:       approval.State,
		RedirectURI: parseRedirectURI(approval.RedirectURI),
	}

	// Restore form values
	fositeReq.Form.Set("response_type", "code")
	fositeReq.Form.Set("redirect_uri", approval.RedirectURI)
	fositeReq.Form.Set("state", approval.State)
	fositeReq.Form.Set("client_id", approval.ClientID)

	// Set PKCE values if present
	if approval.CodeChallenge != "" {
		fositeReq.Form.Set("code_challenge", approval.CodeChallenge)
		fositeReq.Form.Set("code_challenge_method", approval.CodeChallengeMethod)
	}

	// Create session
	session := &fosite.DefaultSession{
		Subject: approval.Subject,
		Extra:   map[string]any{},
	}

	// Grant scopes
	for _, scope := range approval.Scopes {
		fositeReq.GrantScope(scope)
	}

	fositeReq.GrantScope("offline_access")

	// Create the authorization code
	response, err := p.server.Provider().NewAuthorizeResponse(ctx, fositeReq, session)
	if err != nil {
		log.Error(ctx, err, "failed to create authorization response")
		http.Error(writer, "Failed to create authorization", http.StatusInternalServerError)

		return
	}

	// Extract the authorization code from the response
	params := response.GetParameters()
	code := params.Get("code")

	// Store the authorization code for the client to retrieve
	approvalKey := fmt.Sprintf("approved:%s:%s:%s", approval.ClientID, approval.RedirectURI, approval.State)
	// Store with same TTL as the authorization code (typically 10 minutes)
	if err := p.storage.Set(ctx, approvalKey, code, tenMinuteExpiry); err != nil {
		log.Error(ctx, err, "failed to store approval code")
		http.Error(writer, "Failed to store approval", http.StatusInternalServerError)

		return
	}

	// Delete the approval request
	if err := p.storage.DeleteApprovalRequest(approvalID); err != nil {
		// Log but don't fail the request
		log.Warn(ctx, "failed to delete approval request", "id", approvalID, "error", err)
	}

	// Build the complete redirect URL
	redirectURL := fmt.Sprintf("%s?%s", approval.RedirectURI, response.GetParameters().Encode())

	// Return success to admin with instructions
	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(map[string]string{
		"message":      "Approved. The client can now retry their authorization request.",
		"redirect_url": redirectURL,
	}); err != nil {
		log.Error(ctx, err, "failed to encode redirect response")
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)
	}
}

// handleDenyRequest denies and removes a pending authorization request.
func (p *APIProxy) handleDenyRequest(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	approvalID := request.PathValue("id")

	// Check if the approval exists
	_, err := p.storage.GetApprovalRequest(ctx, approvalID)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			http.Error(writer, "Approval request not found", http.StatusNotFound)

			return
		}

		log.Error(ctx, err, "failed to get approval request")
		http.Error(writer, "Failed to get approval", http.StatusInternalServerError)

		return
	}

	// Delete the approval request
	if err := p.storage.DeleteApprovalRequest(approvalID); err != nil {
		log.Error(ctx, err, "failed to delete approval request")
		http.Error(writer, "Failed to delete approval request", http.StatusInternalServerError)

		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

// createApprovalRequest creates a new approval request when auto-approval is disabled.
func (p *APIProxy) createApprovalRequest(
	ctx context.Context,
	authorizeReq *fosite.AuthorizeRequest,
) (*storage.ApprovalRequest, error) {
	approval := &storage.ApprovalRequest{
		ID:                  uuid.New().String(),
		ClientID:            authorizeReq.GetClient().GetID(),
		Subject:             "user", // This would come from authenticated user in production
		Scopes:              authorizeReq.GetRequestedScopes(),
		RedirectURI:         authorizeReq.GetRedirectURI().String(),
		State:               authorizeReq.GetState(),
		CodeChallenge:       authorizeReq.GetRequestForm().Get("code_challenge"),
		CodeChallengeMethod: authorizeReq.GetRequestForm().Get("code_challenge_method"),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(tenMinuteExpiry),
	}

	if err := p.storage.SaveApprovalRequest(ctx, approval); err != nil {
		return nil, fmt.Errorf("failed to save approval request: %w", err)
	}

	return approval, nil
}

// parseRedirectURI safely parses a redirect URI.
func parseRedirectURI(uri string) *url.URL {
	parsed, _ := url.Parse(uri)

	return parsed
}
