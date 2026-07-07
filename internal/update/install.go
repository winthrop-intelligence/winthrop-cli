package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type binaryInstaller struct {
	client Client
}

func (i binaryInstaller) InstallPath(installDir string) (string, error) {
	name := "winthrop"
	if i.client.goos() == "windows" {
		name += ".exe"
	}
	if installDir != "" {
		return filepath.Join(installDir, name), nil
	}
	if i.client.ExecutablePath != "" {
		if err := ensureInstallDirWritable(filepath.Dir(i.client.ExecutablePath)); err != nil {
			return "", fmt.Errorf("current executable directory is not writable: %w; rerun with --install-dir", err)
		}
		return i.client.ExecutablePath, nil
	}
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find current executable: %w", err)
	}
	if err := ensureInstallDirWritable(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("current executable directory is not writable: %w; rerun with --install-dir", err)
	}
	return path, nil
}

func (i binaryInstaller) Install(source string, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".winthrop-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if _, err := io.Copy(tmp, in); err != nil {
		return err
	}
	if err := tmp.Chmod(0755); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (i binaryInstaller) ManualReplaceError(target string, replacement string, cause error) error {
	return fmt.Errorf("replace %s: %w; close running Winthrop processes and move %s to %s", target, cause, replacement, target)
}

func ensureInstallDirWritable(dir string) error {
	file, err := os.CreateTemp(dir, ".winthrop-write-test-*")
	if err != nil {
		return err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return os.Remove(path)
}
