package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type NoticeState struct {
	Path     string
	Now      func() time.Time
	Interval time.Duration
}

type noticeCache struct {
	CheckedAt string `json:"checked_at"`
}

func (s NoticeState) ShouldCheck() bool {
	if os.Getenv(EnvUpdateCheck) == "0" {
		return false
	}
	path, err := s.path()
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var cache noticeCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return true
	}
	checkedAt, err := time.Parse(time.RFC3339, cache.CheckedAt)
	if err != nil {
		return true
	}
	return s.now().Sub(checkedAt) >= s.interval()
}

func (s NoticeState) MarkChecked() error {
	path, err := s.path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	payload, err := json.Marshal(noticeCache{CheckedAt: s.now().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0644)
}

func (s NoticeState) path() (string, error) {
	if s.Path != "" {
		return s.Path, nil
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache dir: %w", err)
	}
	return filepath.Join(cacheDir, "winthrop", "update.json"), nil
}

func (s NoticeState) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s NoticeState) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultCheckInterval
}

func Notice(ctx context.Context, client Client, state NoticeState, currentVersion string) (Status, bool) {
	if !state.ShouldCheck() {
		return Status{}, false
	}
	_ = state.MarkChecked()
	status, err := client.Check(ctx, currentVersion)
	if err != nil || !status.UpdateAvailable {
		return Status{}, false
	}
	return status, true
}
