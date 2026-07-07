package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ArtifactName(tag string, goos string, goarch string) (string, error) {
	if tag == "" {
		return "", errors.New("missing release tag")
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
	switch goos {
	case "linux", "darwin":
		return fmt.Sprintf("winthrop_%s_%s_%s.tar.gz", tag, goos, goarch), nil
	case "windows":
		return fmt.Sprintf("winthrop_%s_%s_%s.zip", tag, goos, goarch), nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}
}

func VerifyChecksum(archivePath string, checksumPath string, artifact string) error {
	expected, err := checksumForArtifact(checksumPath, artifact)
	if err != nil {
		return err
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(sum.Sum(nil))
	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s", artifact)
	}
	return nil
}

func checksumForArtifact(path string, artifact string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == artifact {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("checksum not found for %s", artifact)
}

func ExtractBinary(archivePath string, goos string) (string, error) {
	if strings.HasSuffix(archivePath, ".zip") || goos == "windows" {
		return extractZipBinary(archivePath)
	}
	return extractTarBinary(archivePath)
}

func extractTarBinary(archivePath string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != "winthrop" {
			continue
		}
		return writeTempBinary(reader)
	}
	return "", errors.New("archive did not contain winthrop binary")
}

func extractZipBinary(archivePath string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || filepath.Base(file.Name) != "winthrop.exe" {
			continue
		}
		in, err := file.Open()
		if err != nil {
			return "", err
		}
		tmp, err := writeTempBinary(in)
		if closeErr := in.Close(); err == nil {
			err = closeErr
		}
		return tmp, err
	}
	return "", errors.New("archive did not contain winthrop.exe binary")
}

func writeTempBinary(in io.Reader) (string, error) {
	out, err := os.CreateTemp("", "winthrop-binary-*")
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		_ = out.Close()
		if cleanup {
			_ = os.Remove(out.Name())
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	if err := out.Chmod(0755); err != nil {
		return "", err
	}
	cleanup = false
	return out.Name(), nil
}
