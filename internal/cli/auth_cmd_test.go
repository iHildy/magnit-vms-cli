package cli

import (
	"strings"
	"testing"
)

func TestResolvePasswordProvidedPreservesSpecialCharacters(t *testing.T) {
	app := &App{}
	want := `b5&$^*1h6`

	got, err := resolvePassword(app, want, true, false)
	if err != nil {
		t.Fatalf("resolvePassword returned error: %v", err)
	}
	if got != want {
		t.Fatalf("password mismatch: got %q, want %q", got, want)
	}
}

func TestResolvePasswordFromStdinPreservesContent(t *testing.T) {
	app := &App{Stdin: strings.NewReader("  b5&$^*1h6  \n")}
	want := "  b5&$^*1h6  "

	got, err := resolvePassword(app, "", false, true)
	if err != nil {
		t.Fatalf("resolvePassword returned error: %v", err)
	}
	if got != want {
		t.Fatalf("password mismatch: got %q, want %q", got, want)
	}
}

func TestResolvePasswordRejectsConflictingFlags(t *testing.T) {
	app := &App{Stdin: strings.NewReader("secret\n")}

	_, err := resolvePassword(app, "secret", true, true)
	if err == nil {
		t.Fatal("expected error for conflicting password sources")
	}
}

func TestResolvePasswordFromStdinRejectsEmpty(t *testing.T) {
	app := &App{Stdin: strings.NewReader("\n")}

	_, err := resolvePassword(app, "", false, true)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}
