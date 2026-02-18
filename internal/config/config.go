package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultBaseURL = "https://prowand.pro-unlimited.com"
	configDirName  = "magnit-vms-cli"
	configFileName = "config.yaml"
)

type OutputConfig struct {
	JSONDefault bool `yaml:"json_default,omitempty"`
}

type Config struct {
	BaseURL             string       `yaml:"base_url,omitempty"`
	DefaultEngagementID int64        `yaml:"default_engagement_id,omitempty"`
	Timezone            string       `yaml:"timezone,omitempty"`
	CredentialStore     string       `yaml:"credential_store,omitempty"`
	Output              OutputConfig `yaml:"output,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		BaseURL: defaultBaseURL,
	}
}

func ConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(base, configDirName, configFileName), nil
}

func Load() (Config, string, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, "", err
	}

	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, path, nil
		}
		return Config{}, path, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, path, fmt.Errorf("parse config yaml: %w", err)
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}

	return cfg, path, nil
}

func Save(cfg Config, path string) error {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func ResolveTimezone(cfg Config) (*time.Location, error) {
	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			return nil, fmt.Errorf("invalid configured timezone %q: %w", cfg.Timezone, err)
		}
		return loc, nil
	}

	return time.Now().Location(), nil
}
