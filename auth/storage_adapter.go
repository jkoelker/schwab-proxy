package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/jkoelker/schwab-proxy/storage"
)

// StorageAdapter adapts our storage.Store to work with FositeStore.
type StorageAdapter struct {
	store *storage.Store
}

// NewStorageAdapter creates a new storage adapter.
func NewStorageAdapter(store *storage.Store) *StorageAdapter {
	return &StorageAdapter{store: store}
}

// Set stores a value with optional TTL (StorageInterface compatibility).
func (s *StorageAdapter) Set(key string, value any, ttl time.Duration) error {
	if err := s.store.Set(context.Background(), key, value, ttl); err != nil {
		return fmt.Errorf("storage adapter set failed: %w", err)
	}

	return nil
}

// Get retrieves a value (StorageInterface compatibility).
func (s *StorageAdapter) Get(key string, value any) error {
	if err := s.store.Get(context.Background(), key, value); err != nil {
		return fmt.Errorf("storage adapter get failed: %w", err)
	}

	return nil
}

// SetWithContext stores a value with optional TTL using provided context.
func (s *StorageAdapter) SetWithContext(ctx context.Context, key string, value any, ttl time.Duration) error {
	if err := s.store.Set(ctx, key, value, ttl); err != nil {
		return fmt.Errorf("storage adapter set with context failed: %w", err)
	}

	return nil
}

// GetWithContext retrieves a value using provided context.
func (s *StorageAdapter) GetWithContext(ctx context.Context, key string, value any) error {
	if err := s.store.Get(ctx, key, value); err != nil {
		return fmt.Errorf("storage adapter get with context failed: %w", err)
	}

	return nil
}

// Delete removes a value.
func (s *StorageAdapter) Delete(key string) error {
	if err := s.store.Delete(key); err != nil {
		return fmt.Errorf("storage adapter delete failed: %w", err)
	}

	return nil
}
