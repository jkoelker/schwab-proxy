package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultClientTimeout = 10 * time.Second
)

var (
	ErrBaseURLMissing = errors.New("base URL is required")
	ErrRequestFailed  = errors.New("request failed")
)

// Client wraps access to the schwab-proxy admin HTTP API.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

// Config holds construction parameters for Client.
type Config struct {
	BaseURL  string
	APIKey   string
	Insecure bool
	Timeout  time.Duration
}

// NewClient constructs a Client with sensible defaults.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, ErrBaseURLMissing
	}

	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultClientTimeout
	}

	transport := cloneDefaultTransport()
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // intentional for CLI flag
	}

	return &Client{
		baseURL: parsed,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

func cloneDefaultTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}

	return &http.Transport{}
}

// CreateClientRequest mirrors the API payload.
type CreateClientRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes,omitempty"`
}

// UpdateClientRequest mirrors the API payload with optional fields.
type UpdateClientRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	RedirectURI *string   `json:"redirect_uri,omitempty"`
	Scopes      *[]string `json:"scopes,omitempty"`
	Active      *bool     `json:"active,omitempty"`
}

// ClientResponse matches API response (without secret).
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

// ClientWithSecretResponse includes the secret (only on create).
type ClientWithSecretResponse struct {
	ClientResponse

	Secret string `json:"secret"`
}

// ListClients returns all clients.
func (c *Client) ListClients(ctx context.Context) ([]ClientResponse, error) {
	var out []ClientResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/clients", nil, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// GetClient returns a single client by ID.
func (c *Client) GetClient(ctx context.Context, id string) (*ClientResponse, error) {
	var out ClientResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/clients/"+id, nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// CreateClient creates a new client.
func (c *Client) CreateClient(ctx context.Context, req CreateClientRequest) (*ClientWithSecretResponse, error) {
	var out ClientWithSecretResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/clients", req, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// UpdateClient updates fields on an existing client.
func (c *Client) UpdateClient(ctx context.Context, id string, req UpdateClientRequest) (*ClientResponse, error) {
	var out ClientResponse
	if err := c.doJSON(ctx, http.MethodPut, "/api/clients/"+id, req, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// RotateClientSecret rotates and returns a new plaintext secret once.
func (c *Client) RotateClientSecret(ctx context.Context, id string) (*ClientWithSecretResponse, error) {
	var out ClientWithSecretResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/clients/"+id+"/secret", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteClient removes a client.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/clients/"+id, nil, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, dest any) error {
	req, err := c.buildRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return decodeIfNeeded(resp.Body, dest)
	}

	return buildHTTPError(resp)
}

func (c *Client) buildRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var buf io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}

		buf = bytes.NewBuffer(data)
	}

	u := c.baseURL.ResolveReference(&url.URL{Path: path})

	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func decodeIfNeeded(body io.Reader, dest any) error {
	if dest == nil {
		return nil
	}

	return decodeJSON(body, dest)
}

func buildHTTPError(resp *http.Response) error {
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("%w: status %d", ErrRequestFailed, resp.StatusCode)
	}

	msg := extractErrorMessage(raw)
	if msg == "" {
		return fmt.Errorf("%w: status %d", ErrRequestFailed, resp.StatusCode)
	}

	return fmt.Errorf("%w: status %d: %s", ErrRequestFailed, resp.StatusCode, msg)
}

func decodeJSON(r io.Reader, dest any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

// extractErrorMessage tries to decode common JSON error shapes; falls back to raw text.
func extractErrorMessage(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}

	obj, err := unmarshalError(raw)
	if err != nil {
		return trimmed
	}

	errorCode := stringField(obj, "error")
	message := stringField(obj, "message")
	description := stringField(obj, "error_description")

	if errorCode != "" {
		return joinNonEmpty(errorCode, pickFirstNonEmpty(description, message))
	}

	return pickFirstNonEmpty(message, trimmed)
}

func unmarshalError(raw []byte) (map[string]any, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("decode error body: %w", err)
	}

	return obj, nil
}

func stringField(obj map[string]any, key string) string {
	if val, ok := obj[key].(string); ok {
		return strings.TrimSpace(val)
	}

	return ""
}

func pickFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}

	return ""
}

func joinNonEmpty(first, second string) string {
	if second == "" {
		return first
	}

	return fmt.Sprintf("%s: %s", first, second)
}
