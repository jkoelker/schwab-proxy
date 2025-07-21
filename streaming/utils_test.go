package streaming_test

import (
	"errors"
	"testing"

	"github.com/jkoelker/schwab-proxy/streaming"
)

func TestPrefixRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		clientID  string
		requestID string
		want      string
	}{
		{
			name:      "standard case",
			clientID:  "client_12345",
			requestID: "req_001",
			want:      "client_12345_req_001",
		},
		{
			name:      "empty request ID",
			clientID:  "client_12345",
			requestID: "",
			want:      "client_12345_",
		},
		{
			name:      "request ID with underscores",
			clientID:  "client_12345",
			requestID: "req_with_underscores_123",
			want:      "client_12345_req_with_underscores_123",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := streaming.PrefixRequestID(test.clientID, test.requestID)
			if got != test.want {
				t.Errorf("PrefixRequestID() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUnprefixRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		prefixedID    string
		wantClientID  string
		wantRequestID string
		wantErr       bool
	}{
		{
			name:          "standard case",
			prefixedID:    "client_12345_req_001",
			wantClientID:  "client_12345",
			wantRequestID: "req_001",
			wantErr:       false,
		},
		{
			name:          "request ID with underscores",
			prefixedID:    "client_12345_req_with_underscores_123",
			wantClientID:  "client_12345",
			wantRequestID: "req_with_underscores_123",
			wantErr:       false,
		},
		{
			name:          "empty request ID",
			prefixedID:    "client_12345_",
			wantClientID:  "client_12345",
			wantRequestID: "",
			wantErr:       false,
		},
		{
			name:          "invalid format - missing parts",
			prefixedID:    "client_12345",
			wantClientID:  "",
			wantRequestID: "",
			wantErr:       true,
		},
		{
			name:          "invalid format - no client prefix",
			prefixedID:    "user_12345_req_001",
			wantClientID:  "",
			wantRequestID: "",
			wantErr:       true,
		},
		{
			name:          "invalid format - empty string",
			prefixedID:    "",
			wantClientID:  "",
			wantRequestID: "",
			wantErr:       true,
		},
		{
			name:          "master login request ID",
			prefixedID:    "master_login",
			wantClientID:  "",
			wantRequestID: "",
			wantErr:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gotClientID, gotRequestID, err := streaming.UnprefixRequestID(test.prefixedID)
			if (err != nil) != test.wantErr {
				t.Errorf("UnprefixRequestID() error = %v, wantErr %v", err, test.wantErr)

				return
			}

			// Check that error is wrapped correctly
			if err != nil && !errors.Is(err, streaming.ErrInvalidPrefixedRequestID) {
				t.Errorf("UnprefixRequestID() error type = %T, want wrapped ErrInvalidPrefixedRequestID", err)
			}

			if gotClientID != test.wantClientID {
				t.Errorf("UnprefixRequestID() clientID = %v, want %v", gotClientID, test.wantClientID)
			}

			if gotRequestID != test.wantRequestID {
				t.Errorf("UnprefixRequestID() requestID = %v, want %v", gotRequestID, test.wantRequestID)
			}
		})
	}
}

func TestIsPrefixedRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requestID string
		want      bool
	}{
		{
			name:      "valid prefixed ID",
			requestID: "client_12345_req_001",
			want:      true,
		},
		{
			name:      "valid prefixed ID with underscores in request",
			requestID: "client_12345_req_with_underscores",
			want:      true,
		},
		{
			name:      "invalid - missing parts",
			requestID: "client_12345",
			want:      false,
		},
		{
			name:      "invalid - wrong prefix",
			requestID: "user_12345_req_001",
			want:      false,
		},
		{
			name:      "invalid - empty string",
			requestID: "",
			want:      false,
		},
		{
			name:      "invalid - master login",
			requestID: "master_login",
			want:      false,
		},
		{
			name:      "invalid - single underscore",
			requestID: "client_",
			want:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := streaming.IsPrefixedRequestID(test.requestID); got != test.want {
				t.Errorf("IsPrefixedRequestID() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	// Test that prefix/unprefix are inverse operations
	clientID := "client_abc123"
	requestID := "original_request_456"

	prefixed := streaming.PrefixRequestID(clientID, requestID)

	gotClientID, gotRequestID, err := streaming.UnprefixRequestID(prefixed)
	if err != nil {
		t.Errorf("UnprefixRequestID() unexpected error: %v", err)
	}

	if gotClientID != clientID {
		t.Errorf("Round trip clientID = %v, want %v", gotClientID, clientID)
	}

	if gotRequestID != requestID {
		t.Errorf("Round trip requestID = %v, want %v", gotRequestID, requestID)
	}
}
