package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ory/fosite"
)

// handleAuthorizeRequest wraps the OAuth2 server's authorize handler to support manual approval.
func (p *APIProxy) handleAuthorizeRequest(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// If auto-approval is enabled, just delegate to the auth server
	if p.cfg.AutoApproveAuthorization {
		p.server.HandleAuthorizeRequest(writer, request)

		return
	}

	// Parse the authorization request
	provider := p.server.Provider()

	authorizeRequest, err := provider.NewAuthorizeRequest(ctx, request)
	if err != nil {
		provider.WriteAuthorizeError(ctx, writer, authorizeRequest, err)

		return
	}

	// Check if we have an existing approval for these exact parameters
	clientID := authorizeRequest.GetClient().GetID()
	redirectURI := authorizeRequest.GetRedirectURI().String()
	state := authorizeRequest.GetState()

	// Look for an approved request with matching parameters
	approvedCode, err := p.checkForApprovedRequest(ctx, clientID, redirectURI, state)
	if err == nil && approvedCode != "" {
		// We have an approved request! Complete the authorization
		params := url.Values{}
		params.Set("code", approvedCode)

		if state != "" {
			params.Set("state", state)
		}

		redirectTo := fmt.Sprintf("%s?%s", redirectURI, params.Encode())
		http.Redirect(writer, request, redirectTo, http.StatusFound)

		return
	}

	// Create an approval request in storage
	// Type assert to get the concrete type
	authReq, ok := authorizeRequest.(*fosite.AuthorizeRequest)
	if !ok {
		provider.WriteAuthorizeError(ctx, writer, authorizeRequest,
			fosite.ErrServerError.WithDescription("Invalid request type"))

		return
	}

	approval, err := p.createApprovalRequest(ctx, authReq)
	if err != nil {
		provider.WriteAuthorizeError(ctx, writer, authorizeRequest,
			fosite.ErrServerError.WithDescription("Failed to create approval request"))

		return
	}

	// Return a response indicating manual approval is required
	// If we have a redirect URI, we can include it as a parameter
	if redirectURI != "" {
		params := url.Values{}
		params.Set("error", "approval_pending")
		params.Set("error_description", "Authorization requires manual approval")
		params.Set("approval_id", approval.ID)

		if state != "" {
			params.Set("state", state)
		}

		redirectTo := fmt.Sprintf("%s?%s", redirectURI, params.Encode())
		http.Redirect(writer, request, redirectTo, http.StatusFound)

		return
	}

	// If no redirect URI, just return a JSON response
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusAccepted)

	fmt.Fprintf(
		writer,
		`{"status":"pending","approval_id":"%s","message":"Authorization requires manual approval"}`,
		approval.ID,
	)
}

// checkForApprovedRequest checks if there's an approved authorization for the given parameters.
func (p *APIProxy) checkForApprovedRequest(ctx context.Context, clientID, redirectURI, state string) (string, error) {
	// Create a key based on the request parameters
	key := fmt.Sprintf("approved:%s:%s:%s", clientID, redirectURI, state)

	var code string

	err := p.storage.Get(ctx, key, &code)
	if err != nil {
		return "", fmt.Errorf("failed to check for approved request: %w", err)
	}

	// Delete the approval key since we're using it
	_ = p.storage.Delete(key)

	return code, nil
}
