package auth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/storage"
)

const threeDays = 72 * time.Hour

// TokenServicer defines the interface for token management.
type TokenServicer interface {
	StoreProviderToken(ctx context.Context, accessToken, tokenType, refreshToken string, expiresIn int) error
	GetProviderToken(ctx context.Context) (*oauth2.Token, error)
	NeedsProactiveRefresh(ctx context.Context) bool
}

// TokenService manages OAuth tokens.
type TokenService struct {
	store *storage.Store
}

// TokenClaims represents token information passed through request context.
type TokenClaims struct {
	ClientID string   `json:"client_id"`
	UserID   string   `json:"user_id,omitempty"`
	Scopes   []string `json:"scopes"`
}

// NewTokenService creates a new token service.
func NewTokenService(store *storage.Store) *TokenService {
	return &TokenService{
		store: store,
	}
}

// StoreProviderToken stores an OAuth token from a provider.
func (s *TokenService) StoreProviderToken(
	ctx context.Context,
	accessToken, tokenType, refreshToken string,
	expiresIn int,
) error {
	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
	}

	if err := s.store.Set(ctx, storage.PrefixOAuthToken+"current", token, 0); err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	return nil
}

// GetProviderToken retrieves the current OAuth provider token.
func (s *TokenService) GetProviderToken(ctx context.Context) (*oauth2.Token, error) {
	var token oauth2.Token

	err := s.store.Get(ctx, storage.PrefixOAuthToken+"current", &token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve provider token: %w", err)
	}

	return &token, nil
}

// NeedsProactiveRefresh checks if the token should be refreshed proactively
// Returns true if the token expires in less than 3 days.
func (s *TokenService) NeedsProactiveRefresh(ctx context.Context) bool {
	token, err := s.GetProviderToken(ctx)
	if err != nil {
		// If we can't get the token, assume we should refresh
		log.Error(ctx, err, "Failed to get token for refresh check, assuming refresh needed")

		return true
	}

	timeUntilExpiry := time.Until(token.Expiry)
	needsRefresh := timeUntilExpiry < threeDays

	log.Info(ctx, "Checked token expiry status",
		"expires_at", token.Expiry.Format(time.RFC3339),
		"time_until_expiry", timeUntilExpiry.Round(time.Minute).String(),
		"needs_refresh", needsRefresh)

	return needsRefresh
}
