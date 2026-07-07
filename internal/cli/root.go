package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/api"
	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
	"github.com/winthrop-intelligence/winthrop-cli/internal/oauth"
	"github.com/winthrop-intelligence/winthrop-cli/internal/store"
)

const (
	loginTimeout          = 15 * time.Minute
	requestTimeout        = 30 * time.Second
	tokenRefreshWindow    = 60 * time.Second
	accessTokenTimeFormat = time.RFC3339
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type app struct {
	httpClient    *http.Client
	store         store.Store
	browserOpener func(string) error
}

type cachedAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
}

type accessTokenCacheState int

const (
	accessTokenCacheMissing accessTokenCacheState = iota
	accessTokenCacheReadError
	accessTokenCacheInvalid
	accessTokenCacheUsable
	accessTokenCacheRefreshNeeded
	accessTokenCacheExpired
)

type accessTokenCacheStatus struct {
	Token     oauth.TokenResponse
	ExpiresAt time.Time
	State     accessTokenCacheState
	Err       error
}

func NewRootCommand() *cobra.Command {
	return newRootCommand(app{
		httpClient:    &http.Client{Timeout: requestTimeout},
		store:         store.NewKeyringStore(),
		browserOpener: openBrowser,
	})
}

func newRootCommand(a app) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "winthrop",
		Short:         "Authenticate with Winthrop APIs",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(
		a.loginCommand(),
		a.tokenCommand(),
		a.apiCommand(),
		a.whoamiCommand(),
		a.logoutCommand(),
		a.doctorCommand(),
		versionCommand(),
	)
	return cmd
}

func (a app) loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in with OAuth2 Device Authorization Grant",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return stderrError(cmd, err)
			}
			oc := oauth.Client{Config: cfg, HTTP: a.httpClient}
			ctx, cancel := context.WithTimeout(cmd.Context(), loginTimeout)
			defer cancel()

			device, err := oc.RequestDeviceAuthorization(ctx)
			if err != nil {
				return stderrError(cmd, fmt.Errorf("request device authorization: %w", err))
			}

			verificationURL := device.VerificationURI
			if device.VerificationURIComplete != "" {
				verificationURL = device.VerificationURIComplete
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Open this URL: %s\n", verificationURL)
			fmt.Fprintf(cmd.OutOrStdout(), "Enter code: %s\n", device.UserCode)
			if a.browserOpener != nil && a.browserOpener(verificationURL) == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Opened browser.")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Waiting for authorization...")

			pollCtx := ctx
			if device.ExpiresIn > 0 {
				var pollCancel context.CancelFunc
				pollCtx, pollCancel = context.WithTimeout(ctx, time.Duration(device.ExpiresIn)*time.Second)
				defer pollCancel()
			}
			token, err := oc.PollToken(pollCtx, device)
			if err != nil {
				return stderrError(cmd, fmt.Errorf("login failed: %w", err))
			}
			if token.RefreshToken == "" {
				return stderrError(cmd, errors.New("login succeeded but no refresh token was returned; include offline_access in WINTHROP_SCOPES and run winthrop login again"))
			}

			identity, identityErr := api.Client{Config: cfg, HTTP: a.httpClient}.Me(cmd.Context(), token.AccessToken)
			subject := api.Subject(identity)
			account := store.RefreshAccount(cfg, subject)
			if err := a.store.SaveRefreshToken(account, token.RefreshToken); err != nil {
				return stderrError(cmd, fmt.Errorf("store refresh token: %w", err))
			}
			if err := a.saveAccessToken(account, token, time.Now()); err != nil {
				return stderrError(cmd, fmt.Errorf("cache login access token: %w", err))
			}
			if err := a.store.SetActiveAccount(store.ActiveKey(cfg), account); err != nil {
				return stderrError(cmd, fmt.Errorf("store active login: %w", err))
			}

			if identityErr == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Logged in as:\n%s\n", api.Summary(identity))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Logged in. Could not fetch current user: %v\n", identityErr)
			return nil
		},
	}
}

func (a app) tokenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "Print a short-lived access token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return stderrError(cmd, err)
			}
			token, err := a.refreshAccessToken(cmd.Context(), cfg)
			if err != nil {
				return stderrError(cmd, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), token.AccessToken)
			return nil
		},
	}
}

func (a app) apiCommand() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "api PATH",
		Short: "Make an authenticated GET request to the Winthrop API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return stderrError(cmd, err)
			}
			client := api.Client{Config: cfg, HTTP: streamingHTTPClient(a.httpClient)}
			if _, err := client.ResolvePath(args[0]); err != nil {
				return stderrError(cmd, err)
			}
			token, err := a.refreshAccessToken(cmd.Context(), cfg)
			if err != nil {
				return stderrError(cmd, err)
			}
			resp, err := client.Stream(cmd.Context(), api.Request{
				Method:      http.MethodGet,
				Path:        args[0],
				AccessToken: token.AccessToken,
			})
			if err != nil {
				return stderrError(cmd, err)
			}
			defer resp.Body.Close()
			if verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s %s\n", resp.Method, resp.URL)
				fmt.Fprintf(cmd.ErrOrStderr(), "status: %d\n", resp.StatusCode)
				if contentType := resp.Header.Get("Content-Type"); contentType != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "content-type: %s\n", contentType)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "elapsed: %s\n", resp.Elapsed)
			}
			if (resp.StatusCode < 200 || resp.StatusCode > 299) && isHTMLContentType(resp.Header.Get("Content-Type")) {
				_, _ = io.Copy(io.Discard, resp.Body)
				return stderrError(cmd, apiHTTPError(resp))
			}
			if _, err := io.Copy(cmd.OutOrStdout(), resp.Body); err != nil {
				return stderrError(cmd, err)
			}
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return stderrError(cmd, apiHTTPError(resp))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print safe request and response metadata to stderr")
	return cmd
}

func apiHTTPError(resp api.StreamResponse) error {
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		return fmt.Errorf("API returned HTTP %d (%s)", resp.StatusCode, contentType)
	}
	return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
}

func isHTMLContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return contentType == "text/html" || contentType == "application/xhtml+xml"
}

func streamingHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return http.DefaultClient
	}
	clone := *client
	clone.Timeout = 0
	return &clone
}

func (a app) whoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print the current Winthrop user",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return stderrError(cmd, err)
			}
			token, err := a.refreshAccessToken(cmd.Context(), cfg)
			if err != nil {
				return stderrError(cmd, err)
			}
			identity, err := api.Client{Config: cfg, HTTP: a.httpClient}.Me(cmd.Context(), token.AccessToken)
			if err != nil {
				return stderrError(cmd, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), api.Summary(identity))
			return nil
		},
	}
}

func (a app) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the stored Winthrop login",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return stderrError(cmd, err)
			}
			activeKey := store.ActiveKey(cfg)
			account, err := a.store.GetActiveAccount(activeKey)
			if err != nil && !errors.Is(err, keyring.ErrNotFound) {
				return stderrError(cmd, fmt.Errorf("read stored login: %w", err))
			}
			if account != "" {
				if err := a.store.DeleteRefreshToken(account); err != nil {
					return stderrError(cmd, fmt.Errorf("delete refresh token: %w", err))
				}
				if err := a.store.DeleteAccessToken(account); err != nil {
					return stderrError(cmd, fmt.Errorf("delete cached access token: %w", err))
				}
			}
			if err := a.store.ClearActiveAccount(activeKey); err != nil {
				return stderrError(cmd, fmt.Errorf("clear active login: %w", err))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return nil
		},
	}
}

func (a app) doctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check Winthrop CLI configuration and login state",
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := true
			cfg, err := config.Load()
			if err != nil {
				ok = false
				fmt.Fprintf(cmd.OutOrStdout(), "config: FAIL: %v\n", err)
				fmt.Fprintf(cmd.OutOrStdout(), "fix: export %s=https://auth.example.com %s=https://api.example.com %s=your-client-id\n", config.EnvAuthBaseURL, config.EnvAPIBaseURL, config.EnvClientID)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "config: ok")
			}

			if err := a.store.Available(); err != nil {
				ok = false
				fmt.Fprintf(cmd.OutOrStdout(), "secure storage: FAIL: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), "fix: unlock or configure your OS credential store, then retry.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "secure storage: ok")
			}

			if err == nil {
				if err := checkReachable(cmd.Context(), a.httpClient, cfg.AuthBaseURL); err != nil {
					ok = false
					fmt.Fprintf(cmd.OutOrStdout(), "auth server: FAIL: %v\n", err)
					fmt.Fprintf(cmd.OutOrStdout(), "fix: check %s and network access.\n", config.EnvAuthBaseURL)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "auth server: ok")
				}
				if err := (api.Client{Config: cfg, HTTP: a.httpClient}).Reachable(cmd.Context()); err != nil {
					ok = false
					fmt.Fprintf(cmd.OutOrStdout(), "api server: FAIL: %v\n", err)
					fmt.Fprintf(cmd.OutOrStdout(), "fix: check %s and network access.\n", config.EnvAPIBaseURL)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "api server: ok")
				}

				activeKey := store.ActiveKey(cfg)
				account, err := a.store.GetActiveAccount(activeKey)
				switch {
				case errors.Is(err, keyring.ErrNotFound):
					ok = false
					fmt.Fprintln(cmd.OutOrStdout(), "login: FAIL: no stored login")
					fmt.Fprintln(cmd.OutOrStdout(), "fix: run winthrop login")
				case err != nil:
					ok = false
					fmt.Fprintf(cmd.OutOrStdout(), "login: FAIL: could not read stored login: %v\n", err)
					fmt.Fprintln(cmd.OutOrStdout(), "fix: unlock or configure your OS credential store, then retry.")
				case account == "":
					ok = false
					fmt.Fprintln(cmd.OutOrStdout(), "login: FAIL: stored login is invalid")
					fmt.Fprintln(cmd.OutOrStdout(), "fix: run winthrop logout, then run winthrop login")
				default:
					fmt.Fprintln(cmd.OutOrStdout(), "login: ok")
					fmt.Fprintln(cmd.OutOrStdout(), a.accessTokenCacheSummary(account, time.Now()))
					if _, err := a.refreshAccessToken(cmd.Context(), cfg); err != nil {
						ok = false
						fmt.Fprintf(cmd.OutOrStdout(), "token refresh: FAIL: %v\n", err)
						fmt.Fprintln(cmd.OutOrStdout(), "fix: run winthrop login again")
					} else if account != "" {
						fmt.Fprintln(cmd.OutOrStdout(), "token refresh: ok")
					}
				}
			}

			if !ok {
				return errors.New("doctor found problems")
			}
			return nil
		},
	}
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Winthrop CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "winthrop %s\ncommit: %s\nbuilt: %s\n", version, commit, date)
		},
	}
}

func (a app) refreshAccessToken(ctx context.Context, cfg config.Config) (oauth.TokenResponse, error) {
	activeKey := store.ActiveKey(cfg)
	account, err := a.store.GetActiveAccount(activeKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return oauth.TokenResponse{}, errors.New("not logged in; run winthrop login")
	}
	if err != nil {
		return oauth.TokenResponse{}, fmt.Errorf("read stored login: %w", err)
	}
	if account == "" {
		return oauth.TokenResponse{}, errors.New("stored login is invalid; run winthrop logout, then run winthrop login")
	}
	if status := a.inspectAccessTokenCache(account, time.Now()); status.State == accessTokenCacheUsable {
		return status.Token, nil
	}
	refreshToken, err := a.store.GetRefreshToken(account)
	if errors.Is(err, keyring.ErrNotFound) {
		return oauth.TokenResponse{}, errors.New("could not read stored login; run winthrop login")
	}
	if err != nil {
		return oauth.TokenResponse{}, fmt.Errorf("read refresh token: %w", err)
	}
	token, err := oauth.Client{Config: cfg, HTTP: a.httpClient}.Refresh(ctx, refreshToken)
	if err != nil {
		return oauth.TokenResponse{}, err
	}
	if token.RefreshToken != "" && token.RefreshToken != refreshToken {
		if err := a.store.SaveRefreshToken(account, token.RefreshToken); err != nil {
			return oauth.TokenResponse{}, fmt.Errorf("store rotated refresh token: %w", err)
		}
	}
	if err := a.saveAccessToken(account, token, time.Now()); err != nil {
		return oauth.TokenResponse{}, err
	}
	return token, nil
}

func (a app) inspectAccessTokenCache(account string, now time.Time) accessTokenCacheStatus {
	raw, err := a.store.GetAccessToken(account)
	if errors.Is(err, keyring.ErrNotFound) {
		return accessTokenCacheStatus{State: accessTokenCacheMissing}
	}
	if err != nil {
		return accessTokenCacheStatus{State: accessTokenCacheReadError, Err: err}
	}
	var cached cachedAccessToken
	if err := json.Unmarshal([]byte(raw), &cached); err != nil {
		return accessTokenCacheStatus{State: accessTokenCacheInvalid}
	}
	if cached.AccessToken == "" || cached.ExpiresAt == "" {
		return accessTokenCacheStatus{State: accessTokenCacheInvalid}
	}
	expiresAt, err := time.Parse(accessTokenTimeFormat, cached.ExpiresAt)
	if err != nil {
		return accessTokenCacheStatus{State: accessTokenCacheInvalid}
	}
	status := accessTokenCacheStatus{
		Token:     oauth.TokenResponse{AccessToken: cached.AccessToken},
		ExpiresAt: expiresAt,
	}
	if expiresAt.After(now.Add(tokenRefreshWindow)) {
		status.State = accessTokenCacheUsable
		return status
	}
	if expiresAt.After(now) {
		status.State = accessTokenCacheRefreshNeeded
		return status
	}
	status.State = accessTokenCacheExpired
	return status
}

func (a app) accessTokenCacheSummary(account string, now time.Time) string {
	status := a.inspectAccessTokenCache(account, now)
	switch status.State {
	case accessTokenCacheMissing:
		return "access token cache: missing"
	case accessTokenCacheReadError:
		return fmt.Sprintf("access token cache: unreadable: %v", status.Err)
	case accessTokenCacheInvalid:
		return "access token cache: unreadable"
	case accessTokenCacheUsable:
		return fmt.Sprintf("access token cache: ok, expires at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
	case accessTokenCacheRefreshNeeded:
		return fmt.Sprintf("access token cache: refresh needed, expires at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
	case accessTokenCacheExpired:
		return fmt.Sprintf("access token cache: expired at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
	default:
		return "access token cache: unreadable"
	}
}

func (a app) saveAccessToken(account string, token oauth.TokenResponse, now time.Time) error {
	if token.AccessToken == "" {
		if err := a.store.DeleteAccessToken(account); err != nil {
			return fmt.Errorf("clear cached access token: %w", err)
		}
		return nil
	}
	if token.ExpiresIn <= 0 {
		if err := a.store.DeleteAccessToken(account); err != nil {
			return fmt.Errorf("clear cached access token: %w", err)
		}
		return nil
	}
	cached := cachedAccessToken{
		AccessToken: token.AccessToken,
		ExpiresAt:   now.Add(time.Duration(token.ExpiresIn) * time.Second).Format(accessTokenTimeFormat),
	}
	payload, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("encode cached access token: %w", err)
	}
	if err := a.store.SaveAccessToken(account, string(payload)); err != nil {
		return fmt.Errorf("store cached access token: %w", err)
	}
	return nil
}

func stderrError(cmd *cobra.Command, err error) error {
	return err
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

func checkReachable(ctx context.Context, client *http.Client, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func init() {
	cobra.EnableCommandSorting = false
}
