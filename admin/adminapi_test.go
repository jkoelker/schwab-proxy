package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkoelker/schwab-proxy/admin"
)

func TestNewClientRequiresBaseURL(t *testing.T) {
	t.Parallel()

	if _, err := admin.NewClient(admin.Config{}); err == nil {
		t.Fatalf("expected error for empty base url")
	}
}

func TestCreateClientSendsAuthorization(t *testing.T) {
	t.Parallel()

	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"one","secret":"two"}`))
	}))
	t.Cleanup(srv.Close)

	cli, err := admin.NewClient(admin.Config{BaseURL: srv.URL, APIKey: "abc", Timeout: time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = cli.CreateClient(context.Background(), admin.CreateClientRequest{Name: "n", RedirectURI: "http://example"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if gotAuth != "Bearer abc" {
		t.Fatalf("expected bearer header, got %q", gotAuth)
	}
}

func TestListClientsParsesResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := `[{"id":"c1","name":"n","description":"","redirect_uri":"u",` +
			`"scopes":[],"active":true,"created_at":"","updated_at":""}]`
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)

	cli, err := admin.NewClient(admin.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	clients, err := cli.ListClients(context.Background())
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}

	if len(clients) != 1 || clients[0].ID != "c1" {
		t.Fatalf("unexpected clients: %#v", clients)
	}
}

func TestUpdateClientPropagatesErrorBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	t.Cleanup(srv.Close)

	cli, err := admin.NewClient(admin.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = cli.UpdateClient(context.Background(), "missing", admin.UpdateClientRequest{Name: strPtr("new")})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected propagated error, got %v", err)
	}
}

func TestErrorJSONShape(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid","message":"bad things"}`))
	}))
	t.Cleanup(srv.Close)

	cli, err := admin.NewClient(admin.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = cli.GetClient(context.Background(), "any")
	if err == nil || !strings.Contains(err.Error(), "invalid: bad things") {
		t.Fatalf("expected json error to be parsed, got %v", err)
	}
}

func strPtr(s string) *string { return &s }
