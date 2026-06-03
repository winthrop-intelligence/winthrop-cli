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

func TestLoginReportsMissingRefreshTokenGuidance(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize_device":
			_ = json.NewEncoder(w).Encode(oauth.DeviceAuthorization{
				DeviceCode:      "device",
				UserCode:        "user",
				VerificationURI: "https://verify.example.com",
				ExpiresIn:       60,
				Interval:        1,
			})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token"})
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.NotFoundHandler())
	defer apiServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, apiServer.URL)
	t.Setenv(config.EnvClientID, "client")

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: newFakeStore()})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"login"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "offline_access") {
		t.Fatalf("error = %q", err)
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
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

func TestDoctorDoesNotReportMissingConfigWhenConfigured(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("auth method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("api method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, apiServer.URL)
	t.Setenv(config.EnvClientID, "client")

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: newFakeStore()})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"doctor"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected login failure")
	}

	got := stdout.String()
	if strings.Contains(got, "config: FAIL") {
		t.Fatalf("stdout = %q", got)
	}
	for _, want := range []string{"config: ok", "auth server: ok", "api server: ok", "login: FAIL: no stored login"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout = %q, want %q", got, want)
		}
	}
}

func TestVersionCommandPrintsBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = oldVersion, oldCommit, oldDate
	})
	version, commit, date = "v1.2.3", "abc123", "2026-06-03T00:00:00Z"

	cmd := newRootCommand(app{httpClient: http.DefaultClient, store: newFakeStore()})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"version"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := stdout.String()
	for _, want := range []string{"winthrop v1.2.3", "commit: abc123", "built: 2026-06-03T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout = %q, want %q", got, want)
		}
	}
}
