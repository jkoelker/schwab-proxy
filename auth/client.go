package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

const (
	// clientIDLength is the length of generated client IDs.
	clientIDLength = 24

	// clientSecretLength is the length of generated client secrets.
	clientSecretLength = 32
)

// Client implements fosite.Client interface and serves as the unified client model.
type Client struct {
	ID           string    `json:"id"`
	Secret       []byte    `json:"secret"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	Audience     []string  `json:"audience"`
	Public       bool      `json:"public"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ensureOfflineAccess adds offline_access scope if not already present.
func ensureOfflineAccess(scopes []string) []string {
	for _, scope := range scopes {
		if scope == "offline_access" {
			return scopes
		}
	}

	return append(scopes, "offline_access")
}

// NewClient creates a new client for OAuth2 with given parameters.
func NewClient(id, secret string, redirectURIs []string, scopes []string) *Client {
	now := time.Now()

	return &Client{
		ID:           id,
		Secret:       []byte(secret),
		RedirectURIs: redirectURIs,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       ensureOfflineAccess(scopes),
		Audience:     []string{},
		Public:       false,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ClientWithSecret holds a client and its plaintext secret for API responses.
type ClientWithSecret struct {
	*Client
	PlaintextSecret string `json:"secret"`
}

// NewClientWithDetails creates a new client with auto-generated ID and secret.
func NewClientWithDetails(name, description, redirectURI string, scopes []string) (*ClientWithSecret, error) {
	clientID, err := GenerateRandomString(clientIDLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	secret, err := GenerateRandomString(clientSecretLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	now := time.Now()

	// Hash the client secret using bcrypt (fosite's default expectation)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	client := &Client{
		ID:           clientID,
		Secret:       hashedSecret,
		Name:         name,
		Description:  description,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       ensureOfflineAccess(scopes),
		Audience:     []string{},
		Public:       false,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	return &ClientWithSecret{
		Client:          client,
		PlaintextSecret: secret, // Return the original plaintext secret
	}, nil
}

// GetID returns the client ID.
func (c *Client) GetID() string {
	return c.ID
}

// GetHashedSecret returns the hashed client secret.
func (c *Client) GetHashedSecret() []byte {
	return c.Secret
}

// GetRedirectURIs returns the client's redirect URIs.
func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetGrantTypes returns the allowed grant types.
func (c *Client) GetGrantTypes() fosite.Arguments {
	return c.GrantTypes
}

// GetResponseTypes returns the allowed response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	return []string{"code"}
}

// GetScopes returns the client's allowed scopes.
func (c *Client) GetScopes() fosite.Arguments {
	return c.Scopes
}

// IsPublic returns whether this is a public client.
func (c *Client) IsPublic() bool {
	return c.Public
}

// GetAudience returns the client's audience.
func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}

// GetTokenEndpointAuthMethod returns the client's token endpoint authentication method.
func (c *Client) GetTokenEndpointAuthMethod() string {
	return "client_secret_post" // Allow client secret in POST body
}

// GetSecretString returns the client secret as a string.
func (c *Client) GetSecretString() string {
	return string(c.Secret)
}

// GenerateRandomString creates a random string of the specified length.
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
