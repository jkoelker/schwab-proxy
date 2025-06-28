package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var (
	// ErrApprovalRequestNotFound is returned when an approval request is not
	// found in storage.
	ErrApprovalRequestNotFound = errors.New("approval request not found")

	// ErrApprovalRequestExpired is returned when an approval request has expired.
	ErrApprovalRequestExpired = errors.New("approval request has already expired")
)

// ApprovalRequest represents a pending authorization approval request.
type ApprovalRequest struct {
	ID                  string            `json:"id"`
	ClientID            string            `json:"client_id"`
	Subject             string            `json:"subject"`
	Scopes              []string          `json:"scopes"`
	RedirectURI         string            `json:"redirect_uri"`
	State               string            `json:"state"`
	CodeChallenge       string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod string            `json:"code_challenge_method,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SaveApprovalRequest saves a pending approval request to storage with TTL.
func (s *Store) SaveApprovalRequest(ctx context.Context, req *ApprovalRequest) error {
	key := PrefixApprovalQueue + req.ID

	ttl := time.Until(req.ExpiresAt)
	if ttl < 0 {
		return ErrApprovalRequestExpired
	}

	return s.Set(ctx, key, req, ttl)
}

// GetApprovalRequest retrieves a pending approval request by ID.
func (s *Store) GetApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error) {
	key := PrefixApprovalQueue + id

	var req ApprovalRequest

	if err := s.Get(ctx, key, &req); err != nil {
		return nil, err
	}

	return &req, nil
}

// ListPendingApprovals returns all pending approval requests.
func (s *Store) ListPendingApprovals(ctx context.Context) ([]*ApprovalRequest, error) {
	prefix := []byte(PrefixApprovalQueue)

	var requests []*ApprovalRequest

	if err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key())

			// Get the value
			var req ApprovalRequest
			if err := s.Get(ctx, key, &req); err != nil {
				// Skip items that can't be read
				continue
			}

			requests = append(requests, &req)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to list pending approvals: %w", err)
	}

	return requests, nil
}

// DeleteApprovalRequest removes an approval request from storage.
func (s *Store) DeleteApprovalRequest(id string) error {
	key := PrefixApprovalQueue + id

	return s.Delete(key)
}
