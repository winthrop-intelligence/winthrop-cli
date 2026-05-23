package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
	"github.com/winthrop-intelligence/winthrop-cli/internal/oauth"
	"github.com/winthrop-intelligence/winthrop-cli/internal/store"
)

type fakeStore struct {
	values           map[string]string
	activeAccountErr error
	refreshTokenErr  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{values: map[string]string{}}
}

func (s *fakeStore) Available() error { return nil }

func (s *fakeStore) SaveRefreshToken(account string, token string) error {
	s.values["token:"+account] = token
	return nil
}

func (s *fakeStore) GetRefreshToken(account string) (string, error) {
	if s.refreshTokenErr != nil {
		return "", s.refreshTokenErr
	}
	value, ok := s.values["token:"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (s *fakeStore) DeleteRefreshToken(account string) error {
	delete(s.values, "token:"+account)
	return nil
}

func (s *fakeStore) SetActiveAccount(activeKey string, account string) error {
	s.values["active:"+activeKey] = account
	return nil
}

func (s *fakeStore) GetActiveAccount(activeKey string) (string, error) {
	if s.activeAccountErr != nil {
		return "", s.activeAccountErr
	}
	value, ok := s.values["active:"+activeKey]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (s *fakeStore) ClearActiveAccount(activeKey string) error {
	delete(s.values, "active:"+activeKey)
	return nil
}

func TestTokenCommandPrintsOnlyAccessTokenAndRotatesRefreshToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Fatalf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token", RefreshToken: "new-refresh"})
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.NotFoundHandler())
	defer apiServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, apiServer.URL)
	t.Setenv(config.EnvClientID, "client")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeStore()
	account := store.RefreshAccount(cfg, "subject")
	if err := fake.SaveRefreshToken(account, "old-refresh"); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "access-token\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if got := fake.values["token:"+account]; got != "new-refresh" {
		t.Fatalf("stored refresh = %q", got)
	}
}

func TestRefreshAccessTokenReportsActiveAccountStorageFailure(t *testing.T) {
	cfg := config.Config{AuthBaseURL: "https://auth.example.com", APIBaseURL: "https://api.example.com", ClientID: "client"}
	fake := newFakeStore()
	fake.activeAccountErr = errors.New("keychain locked")

	_, err := app{httpClient: http.DefaultClient, store: fake}.refreshAccessToken(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read stored login: keychain locked") {
		t.Fatalf("error = %q", err)
	}
}

func TestRefreshAccessTokenRejectsEmptyActiveAccount(t *testing.T) {
	cfg := config.Config{AuthBaseURL: "https://auth.example.com", APIBaseURL: "https://api.example.com", ClientID: "client"}
	fake := newFakeStore()
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), ""); err != nil {
		t.Fatal(err)
	}

	_, err := app{httpClient: http.DefaultClient, store: fake}.refreshAccessToken(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stored login is invalid") {
		t.Fatalf("error = %q", err)
	}
}
