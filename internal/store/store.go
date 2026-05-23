package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

const service = "winthrop"

type Store interface {
	Available() error
	SaveRefreshToken(account string, token string) error
	GetRefreshToken(account string) (string, error)
	DeleteRefreshToken(account string) error
	SetActiveAccount(activeKey string, account string) error
	GetActiveAccount(activeKey string) (string, error)
	ClearActiveAccount(activeKey string) error
}

type KeyringStore struct{}

func NewKeyringStore() KeyringStore {
	return KeyringStore{}
}

func ActiveKey(cfg config.Config) string {
	return "active:" + digest(cfg.AuthBaseURL+"\x00"+cfg.ClientID)
}

func RefreshAccount(cfg config.Config, subject string) string {
	if subject == "" {
		subject = "unknown"
	}
	return "refresh:" + digest(cfg.AuthBaseURL+"\x00"+cfg.ClientID+"\x00"+subject)
}

func (KeyringStore) Available() error {
	account := "healthcheck:" + digest(time.Now().UTC().Format(time.RFC3339Nano))
	if err := keyring.Set(service, account, "ok"); err != nil {
		return err
	}
	return keyring.Delete(service, account)
}

func (KeyringStore) SaveRefreshToken(account string, token string) error {
	return keyring.Set(service, account, token)
}

func (KeyringStore) GetRefreshToken(account string) (string, error) {
	return keyring.Get(service, account)
}

func (KeyringStore) DeleteRefreshToken(account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

func (KeyringStore) SetActiveAccount(activeKey string, account string) error {
	return keyring.Set(service, activeKey, account)
}

func (KeyringStore) GetActiveAccount(activeKey string) (string, error) {
	return keyring.Get(service, activeKey)
}

func (KeyringStore) ClearActiveAccount(activeKey string) error {
	err := keyring.Delete(service, activeKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
