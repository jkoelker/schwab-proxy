package storage_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkoelker/schwab-proxy/storage"
)

func TestApprovalQueue(t *testing.T) {
	t.Parallel()

	store := setupStore(t)

	t.Run("SaveAndGetApprovalRequest", func(t *testing.T) {
		t.Parallel()

		approval := &storage.ApprovalRequest{
			ID:                  "test-approval-1",
			ClientID:            "test-client-1",
			Subject:             "user123",
			Scopes:              []string{"read", "write"},
			RedirectURI:         "https://example.com/callback",
			State:               "test-state",
			CodeChallenge:       "challenge123",
			CodeChallengeMethod: "S256",
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(10 * time.Minute),
		}

		ctx := t.Context()

		// Save the approval
		err := store.SaveApprovalRequest(ctx, approval)
		require.NoError(t, err)

		// Retrieve the approval
		retrieved, err := store.GetApprovalRequest(ctx, approval.ID)
		require.NoError(t, err)
		assert.Equal(t, approval.ID, retrieved.ID)
		assert.Equal(t, approval.ClientID, retrieved.ClientID)
		assert.Equal(t, approval.Subject, retrieved.Subject)
		assert.Equal(t, approval.Scopes, retrieved.Scopes)
		assert.Equal(t, approval.RedirectURI, retrieved.RedirectURI)
		assert.Equal(t, approval.State, retrieved.State)
		assert.Equal(t, approval.CodeChallenge, retrieved.CodeChallenge)
		assert.Equal(t, approval.CodeChallengeMethod, retrieved.CodeChallengeMethod)
	})

	t.Run("GetNonExistentApproval", func(t *testing.T) {
		t.Parallel()

		_, err := store.GetApprovalRequest(t.Context(), "non-existent-id")
		assert.ErrorIs(t, err, storage.ErrKeyNotFound)
	})

	t.Run("DeleteApprovalRequest", func(t *testing.T) {
		t.Parallel()

		approval := &storage.ApprovalRequest{
			ID:          "test-approval-delete",
			ClientID:    "test-client-1",
			Subject:     "user123",
			Scopes:      []string{"read"},
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		}

		ctx := t.Context()

		// Save and then delete
		err := store.SaveApprovalRequest(ctx, approval)
		require.NoError(t, err)

		err = store.DeleteApprovalRequest(approval.ID)
		require.NoError(t, err)

		// Verify it's gone
		_, err = store.GetApprovalRequest(ctx, approval.ID)
		assert.ErrorIs(t, err, storage.ErrKeyNotFound)
	})

	t.Run("ListPendingApprovals", func(t *testing.T) {
		t.Parallel()

		// Create a fresh store for this test to avoid interference
		testStore := setupStore(t)

		// Create multiple approvals
		approvals := []*storage.ApprovalRequest{
			{
				ID:          "list-test-1",
				ClientID:    "client-1",
				Subject:     "user1",
				Scopes:      []string{"read"},
				RedirectURI: "https://example.com/callback",
				State:       "state1",
				CreatedAt:   time.Now(),
				ExpiresAt:   time.Now().Add(10 * time.Minute),
			},
			{
				ID:          "list-test-2",
				ClientID:    "client-2",
				Subject:     "user2",
				Scopes:      []string{"write"},
				RedirectURI: "https://example.com/callback",
				State:       "state2",
				CreatedAt:   time.Now(),
				ExpiresAt:   time.Now().Add(10 * time.Minute),
			},
		}

		ctx := t.Context()

		for _, approval := range approvals {
			err := testStore.SaveApprovalRequest(ctx, approval)
			require.NoError(t, err)
		}

		// List all approvals
		listed, err := testStore.ListPendingApprovals(ctx)
		require.NoError(t, err)
		assert.Len(t, listed, 2)

		// Verify we got both approvals
		ids := make(map[string]bool)
		for _, approval := range listed {
			ids[approval.ID] = true
		}

		assert.True(t, ids["list-test-1"])
		assert.True(t, ids["list-test-2"])
	})

	t.Run("ExpiredApprovalNotSaved", func(t *testing.T) {
		t.Parallel()

		approval := &storage.ApprovalRequest{
			ID:          "expired-approval",
			ClientID:    "test-client",
			Subject:     "user123",
			Scopes:      []string{"read"},
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
			CreatedAt:   time.Now().Add(-20 * time.Minute),
			ExpiresAt:   time.Now().Add(-10 * time.Minute), // Already expired
		}

		// Should fail to save
		err := store.SaveApprovalRequest(t.Context(), approval)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already expired")
	})

	t.Run("ApprovalWithTTL", func(t *testing.T) {
		t.Parallel()

		approval := &storage.ApprovalRequest{
			ID:          "ttl-test",
			ClientID:    "test-client",
			Subject:     "user123",
			Scopes:      []string{"read"},
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(2 * time.Second), // Short TTL for testing
		}

		ctx := t.Context()

		// Save the approval
		err := store.SaveApprovalRequest(ctx, approval)
		require.NoError(t, err)

		// Should exist immediately
		_, err = store.GetApprovalRequest(ctx, approval.ID)
		require.NoError(t, err)

		// Wait for TTL to expire
		time.Sleep(3 * time.Second)

		// Should be gone
		_, err = store.GetApprovalRequest(ctx, approval.ID)
		assert.ErrorIs(t, err, storage.ErrKeyNotFound)
	})
}
