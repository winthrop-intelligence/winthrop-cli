package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    int
	}{
		{name: "older", current: "v1.2.2", latest: "v1.2.3", want: -1},
		{name: "equal", current: "v1.2.3", latest: "v1.2.3", want: 0},
		{name: "newer", current: "v1.3.0", latest: "v1.2.3", want: 1},
		{name: "prerelease before stable", current: "v1.2.3-beta.1", latest: "v1.2.3", want: -1},
		{name: "stable after prerelease", current: "v1.2.3", latest: "v1.2.3-beta.1", want: 1},
		{name: "build metadata ignored", current: "v1.2.3+build.1", latest: "v1.2.3+build.2", want: 0},
		{name: "numeric prerelease identifiers", current: "v1.2.3-beta.2", latest: "v1.2.3-beta.10", want: -1},
		{name: "dev fallback", current: "dev", latest: "v1.2.3", want: -1},
		{name: "malformed fallback", current: "bad", latest: "worse", want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareVersions(tt.current, tt.latest)
			switch {
			case tt.want < 0 && got >= 0:
				t.Fatalf("CompareVersions() = %d, want negative", got)
			case tt.want == 0 && got != 0:
				t.Fatalf("CompareVersions() = %d, want zero", got)
			case tt.want > 0 && got <= 0:
				t.Fatalf("CompareVersions() = %d, want positive", got)
			}
		})
	}
}

func TestArtifactName(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{goos: "linux", goarch: "amd64", want: "winthrop_v1.2.3_linux_amd64.tar.gz"},
		{goos: "darwin", goarch: "arm64", want: "winthrop_v1.2.3_darwin_arm64.tar.gz"},
		{goos: "windows", goarch: "amd64", want: "winthrop_v1.2.3_windows_amd64.zip"},
	}
	for _, tt := range tests {
		got, err := ArtifactName("v1.2.3", tt.goos, tt.goarch)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("ArtifactName() = %q, want %q", got, tt.want)
		}
	}
	if _, err := ArtifactName("v1.2.3", "plan9", "amd64"); err == nil {
		t.Fatal("expected unsupported OS error")
	}
}

func TestClientCheckReportsAvailableUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/winthrop-intelligence/winthrop-cli/releases/latest" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3"}`))
	}))
	defer server.Close()

	status, err := (Client{HTTP: server.Client(), APIBaseURL: server.URL}).Check(context.Background(), "v1.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if !status.UpdateAvailable || status.LatestVersion != "v1.2.3" {
		t.Fatalf("status = %+v", status)
	}
}

func TestInstallDownloadsVerifiesAndInstallsTarArtifact(t *testing.T) {
	artifact, err := ArtifactName("v1.2.3", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGzArtifact(t, "winthrop_v1.2.3_linux_amd64/winthrop", "new binary")
	server := releaseServer(t, artifact, archive)
	defer server.Close()

	installDir := t.TempDir()
	result, err := (Client{
		HTTP:            server.Client(),
		APIBaseURL:      server.URL,
		DownloadBaseURL: server.URL,
		GOOS:            "linux",
		GOARCH:          "amd64",
	}).Install(context.Background(), InstallOptions{
		CurrentVersion: "v1.2.2",
		InstallDir:     installDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || result.LatestVersion != "v1.2.3" {
		t.Fatalf("result = %+v", result)
	}
	path := filepath.Join(installDir, "winthrop")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new binary" {
		t.Fatalf("installed binary = %q", string(got))
	}
}

func TestInstallReplacesExecutablePathWhenContainingDirectoryIsWritable(t *testing.T) {
	artifact, err := ArtifactName("v1.2.3", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGzArtifact(t, "winthrop_v1.2.3_linux_amd64/winthrop", "new binary")
	server := releaseServer(t, artifact, archive)
	defer server.Close()

	installDir := t.TempDir()
	target := filepath.Join(installDir, "winthrop")
	if err := os.WriteFile(target, []byte("old binary"), 0555); err != nil {
		t.Fatal(err)
	}

	result, err := (Client{
		HTTP:            server.Client(),
		APIBaseURL:      server.URL,
		DownloadBaseURL: server.URL,
		GOOS:            "linux",
		GOARCH:          "amd64",
		ExecutablePath:  target,
	}).Install(context.Background(), InstallOptions{
		CurrentVersion: "v1.2.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || result.Path != target {
		t.Fatalf("result = %+v", result)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new binary" {
		t.Fatalf("installed binary = %q", string(got))
	}
}

func TestInstallDownloadsVerifiesAndInstallsZipArtifact(t *testing.T) {
	artifact, err := ArtifactName("v1.2.3", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	archive := zipArtifact(t, "winthrop_v1.2.3_windows_amd64/winthrop.exe", "new exe")
	server := releaseServer(t, artifact, archive)
	defer server.Close()

	installDir := t.TempDir()
	_, err = (Client{
		HTTP:            server.Client(),
		APIBaseURL:      server.URL,
		DownloadBaseURL: server.URL,
		GOOS:            "windows",
		GOARCH:          "amd64",
	}).Install(context.Background(), InstallOptions{
		CurrentVersion: "v1.2.2",
		InstallDir:     installDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(installDir, "winthrop.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new exe" {
		t.Fatalf("installed binary = %q", string(got))
	}
}

func TestInstallRejectsChecksumMismatch(t *testing.T) {
	artifact, err := ArtifactName("v1.2.3", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGzArtifact(t, "winthrop_v1.2.3_linux_amd64/winthrop", "new binary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			_, _ = w.Write([]byte(`{"tag_name":"v1.2.3"}`))
		case strings.HasSuffix(r.URL.Path, "/"+artifact):
			_, _ = w.Write(archive)
		case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
			fmt.Fprintf(w, "%064x  %s\n", 0, artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err = (Client{
		HTTP:            server.Client(),
		APIBaseURL:      server.URL,
		DownloadBaseURL: server.URL,
		GOOS:            "linux",
		GOARCH:          "amd64",
	}).Install(context.Background(), InstallOptions{
		CurrentVersion: "v1.2.2",
		InstallDir:     t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestNoticeRespectsCacheAndOptOut(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "update.json")
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	state := NoticeState{Path: cachePath, Now: func() time.Time { return now }}
	if !state.ShouldCheck() {
		t.Fatal("first notice check should be allowed")
	}
	if err := state.MarkChecked(); err != nil {
		t.Fatal(err)
	}
	if state.ShouldCheck() {
		t.Fatal("fresh notice cache should suppress checks")
	}
	t.Setenv(EnvUpdateCheck, "0")
	stale := NoticeState{Path: cachePath, Now: func() time.Time { return now.Add(48 * time.Hour) }}
	if stale.ShouldCheck() {
		t.Fatal("opt-out should suppress notice checks")
	}
}

func releaseServer(t *testing.T, artifact string, archive []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(archive)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			_, _ = w.Write([]byte(`{"tag_name":"v1.2.3"}`))
		case strings.HasSuffix(r.URL.Path, "/"+artifact):
			_, _ = w.Write(archive)
		case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
			fmt.Fprintf(w, "%x  %s\n", sum[:], artifact)
		default:
			http.NotFound(w, r)
		}
	}))
}

func tarGzArtifact(t *testing.T, name string, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipArtifact(t *testing.T, name string, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	file, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
