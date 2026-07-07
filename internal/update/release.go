package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type releaseSource struct {
	client Client
}

type latestRelease struct {
	TagName string `json:"tag_name"`
}

func (s releaseSource) LatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.client.apiBaseURL(), "/")+"/repos/"+s.client.repo()+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.client.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("latest release returned HTTP %d", resp.StatusCode)
	}
	var release latestRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode latest release: %w", err)
	}
	if strings.TrimSpace(release.TagName) == "" {
		return "", errors.New("latest release did not include a tag")
	}
	return release.TagName, nil
}

func (s releaseSource) DownloadVerifiedArchive(ctx context.Context, tag string) (string, error) {
	artifact, err := ArtifactName(tag, s.client.goos(), s.client.goarch())
	if err != nil {
		return "", err
	}
	releaseURL := strings.TrimRight(s.client.downloadBaseURL(), "/") + "/" + s.client.repo() + "/releases/download/" + tag

	tmpdir, err := os.MkdirTemp("", "winthrop-update-*")
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpdir)
		}
	}()

	archivePath := filepath.Join(tmpdir, artifact)
	if err := s.download(ctx, releaseURL+"/"+artifact, archivePath); err != nil {
		return "", err
	}
	checksumPath := filepath.Join(tmpdir, "checksums.txt")
	if err := s.download(ctx, releaseURL+"/checksums.txt", checksumPath); err != nil {
		return "", err
	}
	if err := VerifyChecksum(archivePath, checksumPath, artifact); err != nil {
		return "", err
	}
	cleanup = false
	return archivePath, nil
}

func (s releaseSource) download(ctx context.Context, rawURL string, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}
