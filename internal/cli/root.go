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
	"github.com/winthrop-intelligence/winthrop-cli/internal/update"
)

const (
	loginTimeout          = 15 * time.Minute
	requestTimeout        = 30 * time.Second
	updateNoticeTimeout   = 2 * time.Second
	tokenRefreshWindow    = 60 * time.Second
	accessTokenTimeFormat = time.RFC3339
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type app struct {
	httpClient        *http.Client
	store             store.Store
	browserOpener     func(string) error
	updateClient      update.Client
	updateNoticeState update.NoticeState
	updateNotices     bool
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

type versionOutput struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
}

type whoamiOutput struct {
	Subject  string       `json:"subject"`
	Summary  string       `json:"summary"`
	Identity api.Identity `json:"identity"`
}

type doctorOutput struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
	Fix     string `json:"fix,omitempty"`
	Text    string `json:"-"`
}

type updateOutput struct {
	CurrentVersion  string   `json:"current_version"`
	LatestVersion   string   `json:"latest_version"`
	UpdateAvailable bool     `json:"update_available"`
	Installed       bool     `json:"installed,omitempty"`
	Path            string   `json:"path,omitempty"`
	SuggestedArgv   []string `json:"suggested_argv,omitempty"`
}

const jsonFlagName = "json"

func NewRootCommand() *cobra.Command {
	httpClient := &http.Client{Timeout: requestTimeout}
	return newRootCommand(app{
		httpClient:    httpClient,
		store:         store.NewKeyringStore(),
		browserOpener: openBrowser,
		updateClient: update.Client{
			HTTP: httpClient,
		},
		updateNotices: true,
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
		a.updateCommand(),
		a.versionCommand(),
	)
	return cmd
}

func (a app) loginCommand() *cobra.Command {
	return a.withUpdateNotice(noFileCompletionCommand(&cobra.Command{
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
	}))
}

func (a app) tokenCommand() *cobra.Command {
	return noFileCompletionCommand(&cobra.Command{
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
	})
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
	cmd := noFileCompletionCommand(&cobra.Command{
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
			if jsonOutputRequested(cmd) {
				return writeJSON(cmd, whoamiOutput{
					Subject:  api.Subject(identity),
					Summary:  api.Summary(identity),
					Identity: identity,
				})
			}
			fmt.Fprintln(cmd.OutOrStdout(), api.Summary(identity))
			return nil
		},
	})
	addJSONFlag(cmd)
	return cmd
}

func (a app) logoutCommand() *cobra.Command {
	return noFileCompletionCommand(&cobra.Command{
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
	})
}

func (a app) doctorCommand() *cobra.Command {
	cmd := noFileCompletionCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check Winthrop CLI configuration and login state",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := a.buildDoctorReport(cmd.Context())
			if jsonOutputRequested(cmd) {
				if err := writeJSON(cmd, report); err != nil {
					return err
				}
			} else {
				renderDoctorText(cmd, report)
			}
			if !report.OK {
				return errors.New("doctor found problems")
			}
			return nil
		},
	})
	addJSONFlag(cmd)
	return a.withUpdateNotice(cmd)
}

func (a app) buildDoctorReport(ctx context.Context) doctorOutput {
	report := doctorOutput{OK: true}
	addOK := func(name string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "ok"})
	}
	addFail := func(name string, err error, fix string) {
		report.OK = false
		report.Checks = append(report.Checks, doctorCheck{
			Name:    name,
			Status:  "fail",
			Message: err.Error(),
			Fix:     fix,
		})
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		addFail("config", cfgErr, fmt.Sprintf("export %s=https://auth.example.com %s=https://api.example.com %s=your-client-id", config.EnvAuthBaseURL, config.EnvAPIBaseURL, config.EnvClientID))
	} else {
		addOK("config")
	}

	if err := a.store.Available(); err != nil {
		addFail("secure_storage", err, "unlock or configure your OS credential store, then retry")
	} else {
		addOK("secure_storage")
	}

	if cfgErr != nil {
		return report
	}

	if err := checkReachable(ctx, a.httpClient, cfg.AuthBaseURL); err != nil {
		addFail("auth_server", err, fmt.Sprintf("check %s and network access", config.EnvAuthBaseURL))
	} else {
		addOK("auth_server")
	}
	if err := (api.Client{Config: cfg, HTTP: a.httpClient}).Reachable(ctx); err != nil {
		addFail("api_server", err, fmt.Sprintf("check %s and network access", config.EnvAPIBaseURL))
	} else {
		addOK("api_server")
	}

	activeKey := store.ActiveKey(cfg)
	account, err := a.store.GetActiveAccount(activeKey)
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		addFail("login", errors.New("no stored login"), "run winthrop login")
	case err != nil:
		addFail("login", fmt.Errorf("could not read stored login: %w", err), "unlock or configure your OS credential store, then retry")
	case account == "":
		addFail("login", errors.New("stored login is invalid"), "run winthrop logout, then run winthrop login")
	default:
		addOK("login")
		report.Checks = append(report.Checks, a.accessTokenCacheCheck(account, time.Now()))
		if _, err := a.refreshAccessToken(ctx, cfg); err != nil {
			addFail("token_refresh", err, "run winthrop login again")
		} else {
			addOK("token_refresh")
		}
	}
	return report
}

func renderDoctorText(cmd *cobra.Command, report doctorOutput) {
	for _, check := range report.Checks {
		if check.Text != "" {
			fmt.Fprintln(cmd.OutOrStdout(), check.Text)
			continue
		}
		label := doctorCheckLabel(check.Name)
		if check.Status == "ok" {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: ok\n", label)
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: FAIL: %s\n", label, check.Message)
		if check.Fix != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "fix: %s\n", check.Fix)
		}
	}
}

func doctorCheckLabel(name string) string {
	switch name {
	case "secure_storage":
		return "secure storage"
	case "auth_server":
		return "auth server"
	case "api_server":
		return "api server"
	case "token_refresh":
		return "token refresh"
	default:
		return name
	}
}

func (a app) updateCommand() *cobra.Command {
	var checkOnly bool
	var targetVersion string
	var installDir string
	cmd := noFileCompletionCommand(&cobra.Command{
		Use:   "update",
		Short: "Update the Winthrop CLI",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := a.updateClient
			if client.HTTP == nil {
				client.HTTP = a.httpClient
			}
			if checkOnly {
				status, err := updateStatus(cmd.Context(), client, version, targetVersion)
				if err != nil {
					return stderrError(cmd, err)
				}
				if jsonOutputRequested(cmd) {
					output := updateOutput{
						CurrentVersion:  status.CurrentVersion,
						LatestVersion:   status.LatestVersion,
						UpdateAvailable: status.UpdateAvailable,
					}
					if status.UpdateAvailable {
						output.SuggestedArgv = updateSuggestedArgv(targetVersion)
					}
					return writeJSON(cmd, output)
				}
				if status.UpdateAvailable {
					fmt.Fprintf(cmd.OutOrStdout(), "update available: %s -> %s\n", status.CurrentVersion, status.LatestVersion)
					fmt.Fprintln(cmd.OutOrStdout(), updateCommandSuggestion(targetVersion))
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "winthrop is up to date (%s)\n", status.CurrentVersion)
				return nil
			}
			result, err := client.Install(cmd.Context(), update.InstallOptions{
				CurrentVersion: version,
				TargetVersion:  targetVersion,
				InstallDir:     installDir,
			})
			if err != nil {
				return stderrError(cmd, err)
			}
			if jsonOutputRequested(cmd) {
				return writeJSON(cmd, updateOutput{
					CurrentVersion:  result.CurrentVersion,
					LatestVersion:   result.LatestVersion,
					UpdateAvailable: result.UpdateAvailable,
					Installed:       result.Installed,
					Path:            result.Path,
				})
			}
			if !result.Installed {
				fmt.Fprintf(cmd.OutOrStdout(), "winthrop is up to date (%s)\n", result.CurrentVersion)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "updated winthrop to %s at %s\n", result.LatestVersion, result.Path)
			return nil
		},
	})
	cmd.Flags().BoolVar(&checkOnly, "check", false, "check for an update without installing it")
	cmd.Flags().StringVar(&targetVersion, "version", "", "install a specific release tag")
	cmd.Flags().StringVar(&installDir, "install-dir", "", "install directory for the winthrop binary")
	addJSONFlag(cmd)
	return cmd
}

func updateStatus(ctx context.Context, client update.Client, currentVersion string, targetVersion string) (update.Status, error) {
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion != "" {
		return update.Status{
			CurrentVersion:  currentVersion,
			LatestVersion:   targetVersion,
			UpdateAvailable: update.CompareVersions(currentVersion, targetVersion) < 0,
		}, nil
	}
	return client.Check(ctx, currentVersion)
}

func (a app) versionCommand() *cobra.Command {
	cmd := noFileCompletionCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the Winthrop CLI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutputRequested(cmd) {
				return writeJSON(cmd, versionOutput{Version: version, Commit: commit, Built: date})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "winthrop %s\ncommit: %s\nbuilt: %s\n", version, commit, date)
			return nil
		},
	})
	addJSONFlag(cmd)
	return a.withUpdateNotice(cmd)
}

func noFileCompletionCommand(cmd *cobra.Command) *cobra.Command {
	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return cmd
}

func writeJSON(cmd *cobra.Command, value any) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func addJSONFlag(cmd *cobra.Command) {
	cmd.Flags().Bool(jsonFlagName, false, "print machine-readable JSON")
}

func (a app) withUpdateNotice(cmd *cobra.Command) *cobra.Command {
	preRun := cmd.PreRun
	preRunE := cmd.PreRunE
	if preRunE != nil {
		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if !jsonOutputRequested(cmd) {
				a.maybePrintUpdateNotice(cmd)
			}
			return preRunE(cmd, args)
		}
		return cmd
	}
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		if !jsonOutputRequested(cmd) {
			a.maybePrintUpdateNotice(cmd)
		}
		if preRun != nil {
			preRun(cmd, args)
		}
	}
	return cmd
}

func jsonOutputRequested(cmd *cobra.Command) bool {
	value, err := cmd.Flags().GetBool(jsonFlagName)
	if err != nil {
		return false
	}
	return value
}

func (a app) maybePrintUpdateNotice(cmd *cobra.Command) {
	if !a.updateNotices {
		return
	}
	if err := config.LoadEnvFile(); err != nil {
		return
	}
	client := a.updateClient
	if client.HTTP == nil {
		client.HTTP = a.httpClient
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), updateNoticeTimeout)
	defer cancel()
	status, ok := update.Notice(ctx, client, a.updateNoticeState, version)
	if !ok {
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "notice: winthrop %s is available; run `winthrop update` to install it\n", status.LatestVersion)
}

func updateCommandSuggestion(targetVersion string) string {
	return "run: " + updateSuggestedCommand(targetVersion)
}

func updateSuggestedCommand(targetVersion string) string {
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion == "" {
		return "winthrop update"
	}
	return fmt.Sprintf("winthrop update --version %s", targetVersion)
}

func updateSuggestedArgv(targetVersion string) []string {
	argv := []string{"winthrop", "update", "--json"}
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion != "" {
		argv = append(argv, "--version", targetVersion)
	}
	return argv
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
	return a.accessTokenCacheCheck(account, now).Message
}

func (a app) accessTokenCacheCheck(account string, now time.Time) doctorCheck {
	status := a.inspectAccessTokenCache(account, now)
	switch status.State {
	case accessTokenCacheMissing:
		message := "access token cache: missing"
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "missing", Message: message, Text: message}
	case accessTokenCacheReadError:
		message := fmt.Sprintf("access token cache: unreadable: %v", status.Err)
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "unreadable", Message: message, Text: message}
	case accessTokenCacheInvalid:
		message := "access token cache: unreadable"
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "unreadable", Message: message, Text: message}
	case accessTokenCacheUsable:
		message := fmt.Sprintf("access token cache: ok, expires at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "usable", Message: message, Text: message}
	case accessTokenCacheRefreshNeeded:
		message := fmt.Sprintf("access token cache: refresh needed, expires at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "refresh_needed", Message: message, Text: message}
	case accessTokenCacheExpired:
		message := fmt.Sprintf("access token cache: expired at %s", status.ExpiresAt.Format(accessTokenTimeFormat))
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "expired", Message: message, Text: message}
	default:
		message := "access token cache: unreadable"
		return doctorCheck{Name: "access_token_cache", Status: "ok", Detail: "unreadable", Message: message, Text: message}
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
