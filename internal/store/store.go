package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/zalando/go-keyring"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

const (
	service               = "winthrop"
	healthcheckAccount    = "healthcheck"
	healthcheckCredential = "ok"
)

type Store interface {
	Available() error
	SaveRefreshToken(account string, token string) error
	GetRefreshToken(account string) (string, error)
	DeleteRefreshToken(account string) error
	SaveAccessToken(account string, token string) error
	GetAccessToken(account string) (string, error)
	DeleteAccessToken(account string) error
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

func AccessAccount(refreshAccount string) string {
	return "access:" + digest(refreshAccount)
}

func (KeyringStore) Available() error {
	if err := keyring.Set(service, healthcheckAccount, healthcheckCredential); err != nil {
		return err
	}
	return keyring.Delete(service, healthcheckAccount)
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

func (KeyringStore) SaveAccessToken(account string, token string) error {
	return keyring.Set(service, AccessAccount(account), token)
}

func (KeyringStore) GetAccessToken(account string) (string, error) {
	return keyring.Get(service, AccessAccount(account))
}

func (KeyringStore) DeleteAccessToken(account string) error {
	err := keyring.Delete(service, AccessAccount(account))
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
