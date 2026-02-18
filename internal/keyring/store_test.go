package keyring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ihildy/magnit-vms-cli/internal/config"
)

func isolateConfigHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}

func TestFileStoreRoundTrip(t *testing.T) {
	isolateConfigHome(t)
	t.Setenv(CredentialStoreEnvVar, "")

	want := Credentials{Username: "user@example.com", Password: "secret"}
	if err := SaveCredentialsWithStore(want, StoreFile); err != nil {
		t.Fatalf("save credentials: %v", err)
	}

	got, err := LoadCredentialsWithStore(StoreFile)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if got != want {
		t.Fatalf("unexpected credentials: got=%+v want=%+v", got, want)
	}

	cfgPath, err := config.ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	credPath := filepath.Join(filepath.Dir(cfgPath), credentialsFileName)
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("credentials file stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials permissions: got=%#o want=%#o", info.Mode().Perm(), 0o600)
	}
}

func TestEnvOverrideForcesStore(t *testing.T) {
	isolateConfigHome(t)
	t.Setenv(CredentialStoreEnvVar, StoreFile)

	want := Credentials{Username: "env@example.com", Password: "from-env-store"}
	if err := SaveCredentials(want); err != nil {
		t.Fatalf("save credentials: %v", err)
	}

	got, err := LoadCredentials()
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if got != want {
		t.Fatalf("unexpected credentials: got=%+v want=%+v", got, want)
	}
}

func TestDeleteFromFileNotFound(t *testing.T) {
	isolateConfigHome(t)
	t.Setenv(CredentialStoreEnvVar, "")

	err := DeleteCredentialsWithStore(StoreFile)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestValidateCredentialStore(t *testing.T) {
	valid := []string{"", "AUTO", StoreAuto, StoreKeyring, StoreFile}
	for _, input := range valid {
		if err := ValidateCredentialStore(input); err != nil {
			t.Fatalf("expected valid store %q, got error: %v", input, err)
		}
	}
	if err := ValidateCredentialStore("invalid-store"); err == nil {
		t.Fatalf("expected validation error for invalid store")
	}
}
