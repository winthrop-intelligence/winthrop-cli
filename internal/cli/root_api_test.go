package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
	"github.com/winthrop-intelligence/winthrop-cli/internal/oauth"
	"github.com/winthrop-intelligence/winthrop-cli/internal/store"
)

func newLoggedInAPICommand(t *testing.T, authBaseURL string, apiBaseURL string, client *http.Client, accessToken string) *cobra.Command {
	t.Helper()
	t.Setenv(config.EnvAuthBaseURL, authBaseURL)
	t.Setenv(config.EnvAPIBaseURL, apiBaseURL)
	t.Setenv(config.EnvClientID, "client")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeStore()
	account := store.RefreshAccount(cfg, "subject")
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}
	if accessToken != "" {
		if err := fake.SaveAccessToken(account, cachedTokenPayload(t, accessToken, time.Now().Add(2*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	return newRootCommand(app{httpClient: client, store: fake})
}

func TestAPICommandRefreshesTokenAndPrintsRawJSON(t *testing.T) {
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshes++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("refresh_token") != "refresh-token" {
				t.Fatalf("refresh_token = %q", r.Form.Get("refresh_token"))
			}
			_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token", ExpiresIn: 3600})
		case "/api/v1/coaches.json":
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.RawQuery != "q[first_name_eq]=Jason" {
				t.Fatalf("RawQuery = %q", r.URL.RawQuery)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("Authorization = %q", got)
			}
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Fatalf("Accept = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"first_name":"Jason"}]`))
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(config.EnvAuthBaseURL, server.URL)
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvClientID, "client")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeStore()
	account := store.RefreshAccount(cfg, "subject")
	if err := fake.SaveRefreshToken(account, "refresh-token"); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: server.Client(), store: fake})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"api", "/api/v1/coaches.json?q[first_name_eq]=Jason"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != `[{"id":1,"first_name":"Jason"}]` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d", refreshes)
	}
}

func TestAPICommandVerbosePrintsSafeMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cached-access" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cmd := newLoggedInAPICommand(t, server.URL, server.URL, server.Client(), "cached-access")
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"api", "-v", "/api/v1/users/me"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != `{"ok":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	got := stderr.String()
	for _, want := range []string{"GET " + server.URL + "/api/v1/users/me", "status: 200", "content-type: application/json", "elapsed: "} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want %q", got, want)
		}
	}
	for _, leaked := range []string{"cached-access", "Authorization", "Bearer"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stderr leaked %q: %q", leaked, got)
		}
	}
}

func TestAPICommandPreservesAPIBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/api/v1/users/me" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cmd := newLoggedInAPICommand(t, server.URL, server.URL+"/proxy", server.Client(), "cached-access")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"api", "/api/v1/users/me"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != `{"ok":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAPICommandStreamsWithoutClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("slow"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(25 * time.Millisecond)
		_, _ = w.Write([]byte(" response"))
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = 10 * time.Millisecond
	cmd := newLoggedInAPICommand(t, server.URL, server.URL, httpClient, "cached-access")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"api", "/slow"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "slow response" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAPICommandReturnsErrorAfterPrintingNon2xxBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"missing"}`))
	}))
	defer server.Close()

	cmd := newLoggedInAPICommand(t, server.URL, server.URL, server.Client(), "cached-access")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"api", "/missing"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("ExecuteContext error = nil")
	}
	if !strings.Contains(err.Error(), "API returned HTTP 404") {
		t.Fatalf("error = %v", err)
	}
	if stdout.String() != `{"error":"missing"}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAPICommandSuppressesHTMLNon2xxBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<html><body><h1>404 Not Found</h1></body></html>`))
	}))
	defer server.Close()

	cmd := newLoggedInAPICommand(t, server.URL, server.URL, server.Client(), "cached-access")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"api", "/missing"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("ExecuteContext error = nil")
	}
	if !strings.Contains(err.Error(), "API returned HTTP 404 (text/html; charset=utf-8)") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(stdout.String(), "404 Not Found") {
		t.Fatalf("stdout leaked HTML error body: %q", stdout.String())
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAPICommandRejectsInvalidPathBeforeTokenRefresh(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to %s", r.URL.Path)
	}))
	defer authServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, "https://api.example.com")
	t.Setenv(config.EnvClientID, "client")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeStore()
	account := store.RefreshAccount(cfg, "subject")
	if err := fake.SaveRefreshToken(account, "refresh-token"); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	cmd.SetArgs([]string{"api", "https://api.example.com/api/v1/users/me"})
	err = cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("ExecuteContext error = nil")
	}
	if !strings.Contains(err.Error(), "API path must be relative") {
		t.Fatalf("error = %v", err)
	}
}
