package streaming_test

import (
	"encoding/json"
	"testing"

	"github.com/jkoelker/schwab-proxy/streaming"
)

func TestUserPreferencesPreservesExtraFields(t *testing.T) {
	t.Parallel()

	original := []byte(`{
		"streamerInfo": [{
			"streamerSocketUrl": "wss://streamer-api.schwab.com/ws",
			"schwabClientCustomerId": "123",
			"schwabClientCorrelId": "abc",
			"schwabClientChannel": "channel",
			"schwabClientFunctionId": "function"
		}],
		"otherKey": {"foo": "bar"},
		"boolKey": true
	}`)

	var prefs streaming.UserPreferencesResponse
	if err := json.Unmarshal(original, &prefs); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Modify streamer info to simulate proxy rewrite.
	prefs.StreamerInfo[0].StreamerSocketURL = "ws://proxy/ws/stream"

	modified, err := json.Marshal(prefs)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTrip map[string]any
	if err := json.Unmarshal(modified, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}

	if roundTrip["otherKey"] == nil {
		t.Fatalf("expected otherKey to be preserved, got nil")
	}

	if _, ok := roundTrip["boolKey"].(bool); !ok {
		t.Fatalf("expected boolKey bool to be preserved")
	}

	streamerInfo, ok := roundTrip["streamerInfo"].([]any)
	if !ok || len(streamerInfo) == 0 {
		t.Fatalf("streamerInfo missing after round trip")
	}

	first, ok := streamerInfo[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid streamerInfo element type")
	}

	got := first["streamerSocketUrl"]
	if got != "ws://proxy/ws/stream" {
		t.Fatalf("streamerSocketUrl not updated, got %v", got)
	}
}
