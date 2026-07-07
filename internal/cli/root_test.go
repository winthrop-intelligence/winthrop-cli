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
	"time"

	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
	"github.com/winthrop-intelligence/winthrop-cli/internal/oauth"
	"github.com/winthrop-intelligence/winthrop-cli/internal/store"
)

type fakeStore struct {
	values           map[string]string
	activeAccountErr error
	refreshTokenErr  error
	accessTokenErr   error
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

func (s *fakeStore) SaveAccessToken(account string, token string) error {
	s.values["access:"+account] = token
	return nil
}

func (s *fakeStore) GetAccessToken(account string) (string, error) {
	if s.accessTokenErr != nil {
		return "", s.accessTokenErr
	}
	value, ok := s.values["access:"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (s *fakeStore) DeleteAccessToken(account string) error {
	delete(s.values, "access:"+account)
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

func cachedTokenPayload(t *testing.T, accessToken string, expiresAt time.Time) string {
	t.Helper()
	payload, err := json.Marshal(cachedAccessToken{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt.Format(accessTokenTimeFormat),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func TestLoginStoresRefreshTokenAndActiveAccount(t *testing.T) {
	var openedURL string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize_device":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("client_id") != "client" {
				t.Fatalf("client_id = %q", r.Form.Get("client_id"))
			}
			_ = json.NewEncoder(w).Encode(oauth.DeviceAuthorization{
				DeviceCode:              "device",
				UserCode:                "user-code",
				VerificationURI:         "https://verify.example.com",
				VerificationURIComplete: "https://verify.example.com?code=user-code",
				ExpiresIn:               60,
				Interval:                1,
			})
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("device_code") != "device" {
				t.Fatalf("device_code = %q", r.Form.Get("device_code"))
			}
			_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token", RefreshToken: "refresh-token"})
		default:
			t.Fatalf("auth path = %s", r.URL.Path)
		}
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me" {
			t.Fatalf("api path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "subject", "email": "user@example.com"})
	}))
	defer apiServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, apiServer.URL)
	t.Setenv(config.EnvClientID, "client")

	fake := newFakeStore()
	cmd := newRootCommand(app{
		httpClient: authServer.Client(),
		store:      fake,
		browserOpener: func(rawURL string) error {
			openedURL = rawURL
			return nil
		},
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"login"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	account := store.RefreshAccount(cfg, "subject")
	if got := fake.values["token:"+account]; got != "refresh-token" {
		t.Fatalf("stored refresh = %q", got)
	}
	if got := fake.values["active:"+store.ActiveKey(cfg)]; got != account {
		t.Fatalf("active account = %q", got)
	}
	got := stdout.String()
	for _, want := range []string{"Open this URL: https://verify.example.com?code=user-code", "Enter code: user-code", "Waiting for authorization", "Logged in as:", "id=subject", "email=user@example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout = %q, want %q", got, want)
		}
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if openedURL != "https://verify.example.com?code=user-code" {
		t.Fatalf("opened URL = %q", openedURL)
	}
}

func TestLoginDoesNotOpenBrowserWhenOpenerIsUnset(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize_device":
			_ = json.NewEncoder(w).Encode(oauth.DeviceAuthorization{
				DeviceCode:              "device",
				UserCode:                "user-code",
				VerificationURI:         "https://verify.example.com",
				VerificationURIComplete: "https://verify.example.com?code=user-code",
				ExpiresIn:               60,
				Interval:                1,
			})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token", RefreshToken: "refresh-token"})
		default:
			t.Fatalf("auth path = %s", r.URL.Path)
		}
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "subject"})
	}))
	defer apiServer.Close()

	t.Setenv(config.EnvAuthBaseURL, authServer.URL)
	t.Setenv(config.EnvAPIBaseURL, apiServer.URL)
	t.Setenv(config.EnvClientID, "client")

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: newFakeStore()})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"login"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "Opened browser.") {
		t.Fatalf("stdout = %q", stdout.String())
	}
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
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token", RefreshToken: "new-refresh", ExpiresIn: 3600})
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
	rawCache := fake.values["access:"+account]
	if rawCache == "" {
		t.Fatal("cached access token was not stored")
	}
	var cached cachedAccessToken
	if err := json.Unmarshal([]byte(rawCache), &cached); err != nil {
		t.Fatal(err)
	}
	if cached.AccessToken != "access-token" {
		t.Fatalf("cached access token = %q", cached.AccessToken)
	}
	expiresAt, err := time.Parse(accessTokenTimeFormat, cached.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(expiresAt) < 59*time.Minute {
		t.Fatalf("cached access token expires too soon: %s", cached.ExpiresAt)
	}
}

func TestTokenCommandUsesFreshCachedAccessToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected token refresh")
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
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "cached-access", time.Now().Add(2*time.Minute))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "cached-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestTokenCommandUsesFreshCachedAccessTokenWhenRefreshTokenMissing(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected token refresh")
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
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "cached-access", time.Now().Add(2*time.Minute))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "cached-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestTokenCommandRefreshesExpiredCachedAccessToken(t *testing.T) {
	refreshes := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes++
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "fresh-access", ExpiresIn: 3600})
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
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "expired-access", time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "fresh-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d", refreshes)
	}
}

func TestTokenCommandRefreshesNearlyExpiredCachedAccessToken(t *testing.T) {
	refreshes := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes++
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "fresh-access", ExpiresIn: 3600})
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
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "almost-expired-access", time.Now().Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "fresh-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d", refreshes)
	}
}

func TestTokenCommandIgnoresMalformedCachedAccessToken(t *testing.T) {
	refreshes := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes++
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "fresh-access", ExpiresIn: 3600})
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
	if err := fake.SaveAccessToken(account, "not json"); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "fresh-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d", refreshes)
	}
	if fake.values["access:"+account] == "not json" {
		t.Fatal("malformed cache was not replaced")
	}
}

func TestTokenCommandClearsCachedAccessTokenWhenRefreshOmitsExpiry(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "uncacheable-access"})
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
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "expired-access", time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"token"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "uncacheable-access\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if _, ok := fake.values["access:"+account]; ok {
		t.Fatal("cached access token was not cleared")
	}
}

func TestWhoamiRefreshesTokenAndPrintsIdentity(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Fatalf("auth path = %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("refresh_token") != "refresh-token" {
			t.Fatalf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "access-token"})
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me" {
			t.Fatalf("api path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "subject", "email": "user@example.com"})
	}))
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
	if err := fake.SaveRefreshToken(account, "refresh-token"); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"whoami"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := stdout.String()
	for _, want := range []string{"id=subject", "email=user@example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout = %q, want %q", got, want)
		}
	}
}

func TestLogoutDeletesStoredLogin(t *testing.T) {
	t.Setenv(config.EnvAuthBaseURL, "https://auth.example.com")
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
	if err := fake.SaveAccessToken(account, cachedTokenPayload(t, "cached-access", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCommand(app{httpClient: http.DefaultClient, store: fake})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"logout"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, ok := fake.values["token:"+account]; ok {
		t.Fatalf("refresh token still stored for %q", account)
	}
	if _, ok := fake.values["access:"+account]; ok {
		t.Fatalf("access token still cached for %q", account)
	}
	if _, ok := fake.values["active:"+store.ActiveKey(cfg)]; ok {
		t.Fatalf("active account still stored")
	}
	if stdout.String() != "Logged out.\n" {
		t.Fatalf("stdout = %q", stdout.String())
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

func TestAccessTokenCacheSummaryClassifiesCacheStates(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	account := "refresh:account"

	tests := []struct {
		name       string
		cacheValue string
		cacheErr   error
		want       string
	}{
		{
			name: "missing",
			want: "access token cache: missing",
		},
		{
			name:     "read error",
			cacheErr: errors.New("keychain locked"),
			want:     "access token cache: unreadable: keychain locked",
		},
		{
			name:       "malformed json",
			cacheValue: "not json",
			want:       "access token cache: unreadable",
		},
		{
			name:       "missing access token",
			cacheValue: `{"expires_at":"2026-07-06T12:02:00Z"}`,
			want:       "access token cache: unreadable",
		},
		{
			name:       "malformed timestamp",
			cacheValue: `{"access_token":"cached-access","expires_at":"soon"}`,
			want:       "access token cache: unreadable",
		},
		{
			name:       "usable",
			cacheValue: cachedTokenPayload(t, "cached-access", now.Add(61*time.Second)),
			want:       "access token cache: ok, expires at 2026-07-06T12:01:01Z",
		},
		{
			name:       "exact refresh boundary",
			cacheValue: cachedTokenPayload(t, "cached-access", now.Add(tokenRefreshWindow)),
			want:       "access token cache: refresh needed, expires at 2026-07-06T12:01:00Z",
		},
		{
			name:       "refresh needed",
			cacheValue: cachedTokenPayload(t, "cached-access", now.Add(30*time.Second)),
			want:       "access token cache: refresh needed, expires at 2026-07-06T12:00:30Z",
		},
		{
			name:       "expired",
			cacheValue: cachedTokenPayload(t, "cached-access", now.Add(-time.Second)),
			want:       "access token cache: expired at 2026-07-06T11:59:59Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeStore()
			fake.accessTokenErr = tt.cacheErr
			if tt.cacheValue != "" {
				if err := fake.SaveAccessToken(account, tt.cacheValue); err != nil {
					t.Fatal(err)
				}
			}

			got := (app{store: fake}).accessTokenCacheSummary(account, now)
			if got != tt.want {
				t.Fatalf("summary = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "cached-access") {
				t.Fatalf("summary leaked access token: %q", got)
			}
		})
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

func TestDoctorReportsAccessTokenCacheStatus(t *testing.T) {
	tests := []struct {
		name       string
		cacheValue string
		cacheErr   error
		want       string
	}{
		{
			name:       "usable",
			cacheValue: cachedTokenPayload(t, "cached-access", time.Now().Add(tokenRefreshWindow+time.Minute)),
			want:       "access token cache: ok, expires at ",
		},
		{
			name: "missing",
			want: "access token cache: missing",
		},
		{
			name:       "refresh needed",
			cacheValue: cachedTokenPayload(t, "cached-access", time.Now().Add(tokenRefreshWindow/2)),
			want:       "access token cache: refresh needed, expires at ",
		},
		{
			name:       "expired",
			cacheValue: cachedTokenPayload(t, "cached-access", time.Now().Add(-time.Minute)),
			want:       "access token cache: expired at ",
		},
		{
			name:       "unreadable",
			cacheValue: "not json",
			want:       "access token cache: unreadable",
		},
		{
			name:     "read error",
			cacheErr: errors.New("keychain locked"),
			want:     "access token cache: unreadable: keychain locked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodHead:
					w.WriteHeader(http.StatusOK)
				case http.MethodPost:
					_ = json.NewEncoder(w).Encode(oauth.TokenResponse{AccessToken: "fresh-access", ExpiresIn: 3600})
				default:
					t.Fatalf("auth method = %s", r.Method)
				}
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

			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			fake := newFakeStore()
			fake.accessTokenErr = tt.cacheErr
			account := store.RefreshAccount(cfg, "subject")
			if err := fake.SaveRefreshToken(account, "refresh-token"); err != nil {
				t.Fatal(err)
			}
			if err := fake.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
				t.Fatal(err)
			}
			if tt.cacheValue != "" {
				if err := fake.SaveAccessToken(account, tt.cacheValue); err != nil {
					t.Fatal(err)
				}
			}

			cmd := newRootCommand(app{httpClient: authServer.Client(), store: fake})
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetArgs([]string{"doctor"})
			if err := cmd.ExecuteContext(context.Background()); err != nil {
				t.Fatal(err)
			}

			got := stdout.String()
			if !strings.Contains(got, tt.want) {
				t.Fatalf("stdout = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "cached-access") || strings.Contains(got, "fresh-access") {
				t.Fatalf("stdout leaked access token: %q", got)
			}
			if !strings.Contains(got, "token refresh: ok") {
				t.Fatalf("stdout = %q, want token refresh ok", got)
			}
		})
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
