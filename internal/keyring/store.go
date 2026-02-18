package keyring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihildy/magnit-vms-cli/internal/config"
	zk "github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

const (
	serviceName              = "magnit-vms-cli"
	userKey                  = "username"
	passKey                  = "password"
	credentialsFileName      = "credentials.yaml"
	StoreAuto                = "auto"
	StoreKeyring             = "keyring"
	StoreFile                = "file"
	CredentialStoreEnvVar    = "MAGNIT_CREDENTIAL_STORE"
	defaultCredentialBackend = StoreAuto
)

type Credentials struct {
	Username string
	Password string
}

var ErrCredentialsNotFound = errors.New("credentials not found")

func SaveCredentials(creds Credentials) error {
	return SaveCredentialsWithStore(creds, "")
}

func SaveCredentialsWithStore(creds Credentials, preferredStore string) error {
	if creds.Username == "" {
		return errors.New("username is required")
	}
	if creds.Password == "" {
		return errors.New("password is required")
	}

	store, err := resolveStore(preferredStore)
	if err != nil {
		return err
	}

	switch store {
	case StoreKeyring:
		return saveToKeyring(creds)
	case StoreFile:
		return saveToFile(creds)
	case StoreAuto:
		keyringErr := saveToKeyring(creds)
		if keyringErr == nil {
			return nil
		}
		if fileErr := saveToFile(creds); fileErr != nil {
			return fmt.Errorf("save credentials failed (keyring: %v, file: %w)", keyringErr, fileErr)
		}
		return nil
	default:
		return fmt.Errorf("unsupported credential store %q", store)
	}
}

func LoadCredentials() (Credentials, error) {
	return LoadCredentialsWithStore("")
}

func LoadCredentialsWithStore(preferredStore string) (Credentials, error) {
	store, err := resolveStore(preferredStore)
	if err != nil {
		return Credentials{}, err
	}

	switch store {
	case StoreKeyring:
		return loadFromKeyring()
	case StoreFile:
		return loadFromFile()
	case StoreAuto:
		creds, err := loadFromKeyring()
		if err == nil {
			return creds, nil
		}
		fileCreds, fileErr := loadFromFile()
		if fileErr == nil {
			return fileCreds, nil
		}
		if errors.Is(err, ErrCredentialsNotFound) && errors.Is(fileErr, ErrCredentialsNotFound) {
			return Credentials{}, ErrCredentialsNotFound
		}
		if errors.Is(err, ErrCredentialsNotFound) {
			return Credentials{}, fileErr
		}
		if errors.Is(fileErr, ErrCredentialsNotFound) {
			return Credentials{}, err
		}
		return Credentials{}, fmt.Errorf("load credentials failed (keyring: %v, file: %w)", err, fileErr)
	default:
		return Credentials{}, fmt.Errorf("unsupported credential store %q", store)
	}
}

func DeleteCredentials() error {
	return DeleteCredentialsWithStore("")
}

func DeleteCredentialsWithStore(preferredStore string) error {
	store, err := resolveStore(preferredStore)
	if err != nil {
		return err
	}

	switch store {
	case StoreKeyring:
		return deleteFromKeyring()
	case StoreFile:
		return deleteFromFile()
	case StoreAuto:
		keyringErr := deleteFromKeyring()
		fileErr := deleteFromFile()
		if keyringErr != nil && fileErr != nil {
			return fmt.Errorf("delete credentials failed (keyring: %v, file: %w)", keyringErr, fileErr)
		}
		return nil
	default:
		return fmt.Errorf("unsupported credential store %q", store)
	}
}

func ValidateCredentialStore(store string) error {
	switch normalizeStore(store) {
	case StoreAuto, StoreKeyring, StoreFile:
		return nil
	default:
		return fmt.Errorf("invalid credential store %q (allowed: %s, %s, %s)", store, StoreAuto, StoreKeyring, StoreFile)
	}
}

func NormalizeCredentialStore(store string) string {
	return normalizeStore(store)
}

func saveToKeyring(creds Credentials) error {
	if err := zk.Set(serviceName, userKey, creds.Username); err != nil {
		return fmt.Errorf("save username to keyring: %w", err)
	}
	if err := zk.Set(serviceName, passKey, creds.Password); err != nil {
		return fmt.Errorf("save password to keyring: %w", err)
	}
	return nil
}

func loadFromKeyring() (Credentials, error) {
	username, err := zk.Get(serviceName, userKey)
	if err != nil {
		if errors.Is(err, zk.ErrNotFound) {
			return Credentials{}, ErrCredentialsNotFound
		}
		return Credentials{}, fmt.Errorf("read username from keyring: %w", err)
	}

	password, err := zk.Get(serviceName, passKey)
	if err != nil {
		if errors.Is(err, zk.ErrNotFound) {
			return Credentials{}, ErrCredentialsNotFound
		}
		return Credentials{}, fmt.Errorf("read password from keyring: %w", err)
	}

	return Credentials{Username: username, Password: password}, nil
}

func deleteFromKeyring() error {
	userErr := zk.Delete(serviceName, userKey)
	passErr := zk.Delete(serviceName, passKey)
	if userErr != nil && !errors.Is(userErr, zk.ErrNotFound) {
		return fmt.Errorf("delete username from keyring: %w", userErr)
	}
	if passErr != nil && !errors.Is(passErr, zk.ErrNotFound) {
		return fmt.Errorf("delete password from keyring: %w", passErr)
	}
	return nil
}

func credentialsFilePath() (string, error) {
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfgPath), credentialsFileName), nil
}

func saveToFile(creds Credentials) error {
	path, err := credentialsFilePath()
	if err != nil {
		return fmt.Errorf("resolve credentials path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credentials dir: %w", err)
	}
	data, err := yaml.Marshal(&creds)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	return nil
}

func loadFromFile() (Credentials, error) {
	path, err := credentialsFilePath()
	if err != nil {
		return Credentials{}, fmt.Errorf("resolve credentials path: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credentials{}, ErrCredentialsNotFound
		}
		return Credentials{}, fmt.Errorf("read credentials file: %w", err)
	}
	var creds Credentials
	if err := yaml.Unmarshal(data, &creds); err != nil {
		return Credentials{}, fmt.Errorf("parse credentials file: %w", err)
	}
	if strings.TrimSpace(creds.Username) == "" || creds.Password == "" {
		return Credentials{}, fmt.Errorf("credentials file is missing required fields")
	}
	return creds, nil
}

func deleteFromFile() error {
	path, err := credentialsFilePath()
	if err != nil {
		return fmt.Errorf("resolve credentials path: %w", err)
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("delete credentials file: %w", err)
	}
	return nil
}

func resolveStore(preferredStore string) (string, error) {
	store := strings.TrimSpace(os.Getenv(CredentialStoreEnvVar))
	if store == "" {
		store = preferredStore
	}
	store = normalizeStore(store)
	if err := ValidateCredentialStore(store); err != nil {
		return "", err
	}
	return store, nil
}

func normalizeStore(store string) string {
	value := strings.ToLower(strings.TrimSpace(store))
	if value == "" {
		return defaultCredentialBackend
	}
	return value
}
