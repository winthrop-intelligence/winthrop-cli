package update

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultRepo          = "winthrop-intelligence/winthrop-cli"
	DefaultAPIBaseURL    = "https://api.github.com"
	DefaultDownloadURL   = "https://github.com"
	DefaultCheckInterval = 24 * time.Hour
	EnvUpdateCheck       = "WINTHROP_UPDATE_CHECK"
)

type Client struct {
	HTTP            *http.Client
	Repo            string
	APIBaseURL      string
	DownloadBaseURL string
	GOOS            string
	GOARCH          string
	ExecutablePath  string
}

type Status struct {
	CurrentVersion  string
	LatestVersion   string
	UpdateAvailable bool
}

type InstallOptions struct {
	CurrentVersion string
	TargetVersion  string
	InstallDir     string
}

type InstallResult struct {
	Status
	Installed bool
	Path      string
}

func (c Client) Check(ctx context.Context, currentVersion string) (Status, error) {
	latest, err := c.LatestVersion(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{
		CurrentVersion:  currentVersion,
		LatestVersion:   latest,
		UpdateAvailable: CompareVersions(currentVersion, latest) < 0,
	}, nil
}

func (c Client) LatestVersion(ctx context.Context) (string, error) {
	return releaseSource{client: c}.LatestVersion(ctx)
}

func (c Client) Install(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	targetVersion := strings.TrimSpace(opts.TargetVersion)
	if targetVersion == "" {
		var err error
		targetVersion, err = c.LatestVersion(ctx)
		if err != nil {
			return InstallResult{}, err
		}
	}
	status := Status{
		CurrentVersion:  opts.CurrentVersion,
		LatestVersion:   targetVersion,
		UpdateAvailable: CompareVersions(opts.CurrentVersion, targetVersion) < 0,
	}
	if opts.TargetVersion == "" && !status.UpdateAvailable {
		return InstallResult{Status: status}, nil
	}

	source := releaseSource{client: c}
	archive, err := source.DownloadVerifiedArchive(ctx, targetVersion)
	if err != nil {
		return InstallResult{}, err
	}
	defer os.RemoveAll(filepath.Dir(archive))

	binary, err := ExtractBinary(archive, c.goos())
	if err != nil {
		return InstallResult{}, err
	}
	cleanupBinary := true
	defer func() {
		if cleanupBinary {
			_ = os.Remove(binary)
		}
	}()

	installer := binaryInstaller{client: c}
	target, err := installer.InstallPath(opts.InstallDir)
	if err != nil {
		return InstallResult{}, err
	}
	if err := installer.Install(binary, target); err != nil {
		if c.goos() == "windows" {
			manualPath := target + ".new"
			if copyErr := installer.Install(binary, manualPath); copyErr == nil {
				return InstallResult{}, installer.ManualReplaceError(target, manualPath, err)
			}
			cleanupBinary = false
			return InstallResult{}, installer.ManualReplaceError(target, binary, err)
		}
		return InstallResult{}, err
	}

	return InstallResult{Status: status, Installed: true, Path: target}, nil
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c Client) repo() string {
	if c.Repo != "" {
		return c.Repo
	}
	return DefaultRepo
}

func (c Client) apiBaseURL() string {
	if c.APIBaseURL != "" {
		return c.APIBaseURL
	}
	return DefaultAPIBaseURL
}

func (c Client) downloadBaseURL() string {
	if c.DownloadBaseURL != "" {
		return c.DownloadBaseURL
	}
	return DefaultDownloadURL
}

func (c Client) goos() string {
	if c.GOOS != "" {
		return c.GOOS
	}
	return runtime.GOOS
}

func (c Client) goarch() string {
	if c.GOARCH != "" {
		return c.GOARCH
	}
	return runtime.GOARCH
}
