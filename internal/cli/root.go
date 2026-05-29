package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/api"
	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
	"github.com/winthrop-intelligence/winthrop-cli/internal/oauth"
	"github.com/winthrop-intelligence/winthrop-cli/internal/store"
)

const (
	loginTimeout   = 15 * time.Minute
	requestTimeout = 30 * time.Second
)

type app struct {
	httpClient *http.Client
	store      store.Store
}

func NewRootCommand() *cobra.Command {
	return newRootCommand(app{
		httpClient: &http.Client{Timeout: requestTimeout},
		store:      store.NewKeyringStore(),
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
		a.whoamiCommand(),
		a.logoutCommand(),
		a.doctorCommand(),
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
			if err := openBrowser(verificationURL); err == nil {
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
	return token, nil
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
