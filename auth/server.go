package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/storage"
)

const (
	// expectedTokenParts is the expected number of parts in a fosite token.
	expectedTokenParts = 2
)

// Storage implements fosite.Storage interface using our storage backend.
type Storage struct {
	storage StorageInterface
	cfg     *config.Config
}

// Ensure Storage implements required interfaces.
var (
	_ fosite.ClientManager = (*Storage)(nil)
	_ fosite.Storage       = (*Storage)(nil)
)

// StorageInterface defines what we need from our storage.
type StorageInterface interface {
	Set(key string, value any, ttl time.Duration) error
	Get(key string, value any) error
	Delete(key string) error
}

// Server wraps Fosite OAuth2 provider.
type Server struct {
	provider fosite.OAuth2Provider
	store    *Storage
	cfg      *config.Config
}

// NewServer creates a new OAuth2 server using Fosite.
func NewServer(store StorageInterface, cfg *config.Config, jwtSigningKey []byte) (*Server, error) {
	storage := &Storage{
		storage: store,
		cfg:     cfg,
	}

	// Configure Fosite with configurable OAuth2 support
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        cfg.OAuth2AccessTokenExpiry,
		RefreshTokenLifespan:       cfg.OAuth2RefreshTokenExpiry,
		AuthorizeCodeLifespan:      cfg.OAuth2AuthCodeExpiry,
		GlobalSecret:               jwtSigningKey,
		SendDebugMessagesToClients: cfg.SendDebugMessagesToClients,
	}

	// Create OAuth2 provider with both client credentials and authorization code flows
	provider := compose.Compose(
		fositeConfig,
		storage,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig),
		},
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
	)

	return &Server{
		provider: provider,
		store:    storage,
		cfg:      cfg,
	}, nil
}

// Provider returns the fosite OAuth2 provider.
func (s *Server) Provider() fosite.OAuth2Provider {
	return s.provider
}

// Storage returns the auth storage.
func (s *Server) Storage() *Storage {
	return s.store
}

// HandleAuthorizeRequest handles OAuth2 authorization requests.
func (s *Server) HandleAuthorizeRequest(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Parse the authorization request
	authorizeRequest, err := s.provider.NewAuthorizeRequest(ctx, request)
	if err != nil {
		s.provider.WriteAuthorizeError(ctx, writer, authorizeRequest, err)

		return
	}

	// In a real implementation, you would:
	// 1. Authenticate the user
	// 2. Show consent screen if needed
	// 3. Check permissions

	// For now, auto-approve all requests (ONLY for demo/testing)
	// Create a basic session
	session := &fosite.DefaultSession{
		Subject: "user123", // This would come from authenticated user
		Extra:   map[string]any{},
	}

	// Ensure the request has an ID
	authorizeRequest.SetID(uuid.New().String())

	// Grant all requested scopes (in production, implement proper consent)
	for _, scope := range authorizeRequest.GetRequestedScopes() {
		authorizeRequest.GrantScope(scope)
	}

	// Always grant offline_access to ensure refresh tokens are issued
	authorizeRequest.GrantScope("offline_access")

	// Create the response
	response, err := s.provider.NewAuthorizeResponse(ctx, authorizeRequest, session)
	if err != nil {
		s.provider.WriteAuthorizeError(ctx, writer, authorizeRequest, err)

		return
	}

	// Write the response
	s.provider.WriteAuthorizeResponse(ctx, writer, authorizeRequest, response)
}

// HandleTokenRequest handles OAuth2 token requests.
func (s *Server) HandleTokenRequest(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	_ = request.ParseForm()

	// Create a new session for the token request
	session := &fosite.DefaultSession{
		Extra: map[string]any{},
	}

	// Parse the token request
	tokenRequest, err := s.provider.NewAccessRequest(ctx, request, session)
	if err != nil {
		s.provider.WriteAccessError(ctx, writer, tokenRequest, err)

		return
	}

	// Grant the access request
	response, err := s.provider.NewAccessResponse(ctx, tokenRequest)
	if err != nil {
		s.provider.WriteAccessError(ctx, writer, tokenRequest, err)

		return
	}

	// Write the response
	s.provider.WriteAccessResponse(ctx, writer, tokenRequest, response)
}

// Implement required fosite.Storage interface methods

func (s *Storage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	var client Client

	key := storage.PrefixClient + id

	if err := s.storage.Get(key, &client); err != nil {
		return nil, fosite.ErrNotFound
	}

	return &client, nil
}

func (s *Storage) ClientAssertionJWTValid(_ context.Context, _ string) error {
	// Implement JWT assertion validation if needed
	return nil
}

func (s *Storage) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	// Store JWT assertion if needed
	return nil
}

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	// Store essential data fields from the requester (like fosite example but for persistence)
	data := map[string]any{
		"client_id":          req.GetClient().GetID(),
		"granted_scopes":     req.GetGrantedScopes(),
		"requested_scopes":   req.GetRequestedScopes(),
		"requested_at":       req.GetRequestedAt().Format(time.RFC3339),
		"request_id":         req.GetID(),
		"form":               req.GetRequestForm(),
		"requested_audience": req.GetRequestedAudience(),
		"granted_audience":   req.GetGrantedAudience(),
		"active":             true, // Mirror fosite example's active flag
	}

	// Store session data if it exists
	if session := req.GetSession(); session != nil {
		if defaultSession, ok := session.(*fosite.DefaultSession); ok {
			data["session_subject"] = defaultSession.Subject
			data["session_extra"] = defaultSession.Extra
		}
	}

	// Create PKCE session since fosite expects it for authorization code flow
	err := s.CreatePKCERequestSession(ctx, code, req)
	if err != nil {
		return err
	}

	if err := s.storage.Set("authcode:"+code, data, s.cfg.OAuth2AuthCodeExpiry); err != nil {
		return fmt.Errorf("failed to store authorization code: %w", err)
	}

	return nil
}

func (s *Storage) GetAuthorizeCodeSession(
	ctx context.Context,
	code string,
	session fosite.Session,
) (fosite.Requester, error) {
	data, err := s.getAuthorizeCodeData(code)
	if err != nil {
		return nil, err
	}

	client, err := s.getClientFromData(ctx, data)
	if err != nil {
		return nil, err
	}

	req := fosite.NewRequest()
	req.Client = client

	s.restoreRequestData(req, data)
	s.restoreSessionData(req, data, session)

	return req, nil
}

func (s *Storage) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	var data map[string]any

	err := s.storage.Get("authcode:"+code, &data)
	if err != nil {
		return fosite.ErrNotFound
	}

	data["active"] = false

	if err := s.storage.Set("authcode:"+code, data, s.cfg.OAuth2AuthCodeExpiry); err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %w", err)
	}

	return nil
}

func (s *Storage) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	data := map[string]any{
		"client_id":    req.GetClient().GetID(),
		"scopes":       req.GetGrantedScopes(),
		"session":      req.GetSession(),
		"requested_at": req.GetRequestedAt(),
	}

	if err := s.storage.Set("access:"+signature, data, s.cfg.OAuth2AccessTokenExpiry); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	return nil
}

func (s *Storage) GetAccessTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	var data map[string]any

	err := s.storage.Get("access:"+signature, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	clientID, ok := data["client_id"].(string)
	if !ok {
		return nil, fosite.ErrNotFound
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	req := fosite.NewRequest()
	req.Client = client
	req.Session = session

	if scopes, ok := data["scopes"].([]any); ok {
		for _, scope := range scopes {
			if scopeStr, ok := scope.(string); ok {
				req.GrantScope(scopeStr)
			}
		}
	}

	return req, nil
}

func (s *Storage) DeleteAccessTokenSession(_ context.Context, signature string) error {
	if err := s.storage.Delete("access:" + signature); err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	return nil
}

func (s *Storage) CreateRefreshTokenSession(
	_ context.Context,
	signature string,
	accessSignature string,
	req fosite.Requester,
) error {
	data := map[string]any{
		"client_id":        req.GetClient().GetID(),
		"scopes":           req.GetGrantedScopes(),
		"session":          req.GetSession(),
		"requested_at":     req.GetRequestedAt(),
		"access_signature": accessSignature,
	}

	if err := s.storage.Set("refresh:"+signature, data, s.cfg.OAuth2RefreshTokenExpiry); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

func (s *Storage) GetRefreshTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	var data map[string]any

	err := s.storage.Get("refresh:"+signature, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	clientID, ok := data["client_id"].(string)
	if !ok {
		return nil, fosite.ErrNotFound
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	req := fosite.NewRequest()
	req.Client = client
	req.Session = session

	if scopes, ok := data["scopes"].([]any); ok {
		for _, scope := range scopes {
			if scopeStr, ok := scope.(string); ok {
				req.GrantScope(scopeStr)
			}
		}
	}

	return req, nil
}

func (s *Storage) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	if err := s.storage.Delete("refresh:" + signature); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *Storage) RevokeRefreshToken(_ context.Context, requestID string) error {
	if err := s.storage.Delete("refresh:" + requestID); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

func (s *Storage) RevokeAccessToken(_ context.Context, requestID string) error {
	if err := s.storage.Delete("access:" + requestID); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	return nil
}

// Authenticate is required by fosite.Storage but can be no-ops for basic implementation.
func (s *Storage) Authenticate(_ context.Context, _ string) error {
	return nil
}

func (s *Storage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, _ string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

func (s *Storage) RotateRefreshToken(_ context.Context, _ string, refreshTokenSignature string) error {
	// For basic implementation, we just delete the old refresh token
	// In a more sophisticated implementation, you might want to store rotation info
	if err := s.storage.Delete("refresh:" + refreshTokenSignature); err != nil {
		return fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return nil
}

// Additional required methods for oauth2.CoreStorage interface

func (s *Storage) CreatePKCERequestSession(_ context.Context, signature string, req fosite.Requester) error {
	data := map[string]any{
		"client_id":    req.GetClient().GetID(),
		"scopes":       req.GetGrantedScopes(),
		"session":      req.GetSession(),
		"requested_at": req.GetRequestedAt(),
	}

	if err := s.storage.Set("pkce:"+signature, data, s.cfg.OAuth2AuthCodeExpiry); err != nil {
		return fmt.Errorf("failed to store PKCE request: %w", err)
	}

	return nil
}

func (s *Storage) GetPKCERequestSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	var data map[string]any

	err := s.storage.Get("pkce:"+signature, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to get PKCE request: %w", err)
	}

	clientID, ok := data["client_id"].(string)
	if !ok {
		return nil, fosite.ErrNotFound
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	req := fosite.NewRequest()
	req.Client = client
	req.Session = session

	if scopes, ok := data["scopes"].([]any); ok {
		for _, scope := range scopes {
			if scopeStr, ok := scope.(string); ok {
				req.GrantScope(scopeStr)
			}
		}
	}

	return req, nil
}

func (s *Storage) DeletePKCERequestSession(_ context.Context, signature string) error {
	if err := s.storage.Delete("pkce:" + signature); err != nil {
		return fmt.Errorf("failed to delete PKCE request: %w", err)
	}

	return nil
}

// ValidateAccessToken validates an access token and returns client info.
func (s *Server) ValidateAccessToken(ctx context.Context, token string) (string, []string, error) {
	// Extract the signature from the fosite token
	// Fosite tokens have the format: ory_at_<prefix>.<signature>
	parts := strings.Split(token, ".")
	if len(parts) != expectedTokenParts {
		return "", nil, fosite.ErrInvalidRequest.WithDescription("Invalid token format")
	}

	signature := parts[1]

	// Look up the access token session directly using the signature
	session := &fosite.DefaultSession{}

	accessReq, err := s.store.GetAccessTokenSession(ctx, signature, session)
	if err != nil {
		return "", nil, err
	}

	clientID := accessReq.GetClient().GetID()
	scopes := accessReq.GetGrantedScopes()

	return clientID, scopes, nil
}

// getAuthorizeCodeData retrieves and validates authorization code data.
func (s *Storage) getAuthorizeCodeData(code string) (map[string]any, error) {
	var data map[string]any

	err := s.storage.Get("authcode:"+code, &data)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	// Check if the session is active
	if active, ok := data["active"].(bool); ok && !active {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	return data, nil
}

// getClientFromData extracts client information from stored data.
func (s *Storage) getClientFromData(ctx context.Context, data map[string]any) (fosite.Client, error) {
	clientID, ok := data["client_id"].(string)
	if !ok {
		return nil, fosite.ErrNotFound
	}

	return s.GetClient(ctx, clientID)
}

// restoreRequestData restores request data from stored authorization code data.
func (s *Storage) restoreRequestData(req *fosite.Request, data map[string]any) {
	// Restore request ID
	if requestID, ok := data["request_id"].(string); ok {
		req.SetID(requestID)
	}

	s.restoreFormData(req, data)
	s.restoreTimestamp(req, data)
	s.restoreScopes(req, data)
	s.restoreAudience(req, data)
}

// restoreFormData restores form data from stored data.
func (s *Storage) restoreFormData(req *fosite.Request, data map[string]any) {
	formData, ok := data["form"].(map[string]any)
	if !ok {
		return
	}

	for key, value := range formData {
		switch typedValue := value.(type) {
		case []any:
			stringSlice := make([]string, len(typedValue))

			for i, item := range typedValue {
				if str, ok := item.(string); ok {
					stringSlice[i] = str
				}
			}

			req.Form[key] = stringSlice
		case []string:
			req.Form[key] = typedValue
		case string:
			req.Form[key] = []string{typedValue}
		}
	}
}

// restoreTimestamp restores timestamp from stored data.
func (s *Storage) restoreTimestamp(req *fosite.Request, data map[string]any) {
	if requestedAt, ok := data["requested_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, requestedAt); err == nil {
			req.RequestedAt = parsed
		}
	}
}

// restoreScopes restores requested and granted scopes from stored data.
func (s *Storage) restoreScopes(req *fosite.Request, data map[string]any) {
	if requestedScopes, ok := data["requested_scopes"].([]any); ok {
		for _, scope := range requestedScopes {
			if scopeStr, ok := scope.(string); ok {
				req.AppendRequestedScope(scopeStr)
			}
		}
	}

	if grantedScopes, ok := data["granted_scopes"].([]any); ok {
		for _, scope := range grantedScopes {
			if scopeStr, ok := scope.(string); ok {
				req.GrantScope(scopeStr)
			}
		}
	}
}

// restoreAudience restores audience data from stored data.
func (s *Storage) restoreAudience(req *fosite.Request, data map[string]any) {
	if requestedAud, ok := data["requested_audience"].([]any); ok {
		for _, aud := range requestedAud {
			if audStr, ok := aud.(string); ok {
				req.AppendRequestedAudience(audStr)
			}
		}
	}

	if grantedAud, ok := data["granted_audience"].([]any); ok {
		for _, aud := range grantedAud {
			if audStr, ok := aud.(string); ok {
				req.GrantAudience(audStr)
			}
		}
	}
}

// restoreSessionData restores session data from stored data.
func (s *Storage) restoreSessionData(req *fosite.Request, data map[string]any, session fosite.Session) {
	if session == nil {
		session = &fosite.DefaultSession{}
	}

	if defaultSession, ok := session.(*fosite.DefaultSession); ok {
		if subject, ok := data["session_subject"].(string); ok {
			defaultSession.Subject = subject
		}

		if extra, ok := data["session_extra"].(map[string]any); ok {
			defaultSession.Extra = extra
		}
	}

	req.SetSession(session)
}
