package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ihildy/magnit-vms-hour-logging-cli/internal/auth"
	"github.com/ihildy/magnit-vms-hour-logging-cli/internal/keyring"
	"github.com/ihildy/magnit-vms-hour-logging-cli/internal/output"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newAuthCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication credentials",
	}
	cmd.AddCommand(newAuthLoginCmd(app))
	cmd.AddCommand(newAuthStatusCmd(app))
	cmd.AddCommand(newAuthLogoutCmd(app))
	return cmd
}

func newAuthLoginCmd(app *App) *cobra.Command {
	var username string
	var password string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store credentials in keychain and verify login",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if strings.TrimSpace(username) == "" {
				fmt.Fprint(app.Stderr, "Username: ")
				reader := bufio.NewReader(app.Stdin)
				line, err := reader.ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				username = strings.TrimSpace(line)
			}
			if username == "" {
				return fmt.Errorf("username is required")
			}

			passwordFlagSet := cmd.Flags().Changed("password")
			passwordFromStdin, err := cmd.Flags().GetBool("password-stdin")
			if err != nil {
				return err
			}

			password, err := resolvePassword(app, password, passwordFlagSet, passwordFromStdin)
			if err != nil {
				return err
			}

			httpClient, err := auth.NewHTTPClient()
			if err != nil {
				return err
			}
			authn := &auth.Authenticator{BaseURL: app.BaseURL(), Client: httpClient}
			if err := authn.Login(ctx, username, password); err != nil {
				return err
			}

			user, err := authn.CurrentUser(ctx)
			if err != nil {
				return err
			}

			if err := keyring.SaveCredentials(keyring.Credentials{Username: username, Password: password}); err != nil {
				return err
			}

			payload := map[string]any{
				"ok":        true,
				"operation": "auth_login",
				"username":  username,
				"user": map[string]any{
					"userId":   user["userId"],
					"fullName": user["fullName"],
					"email":    user["email"],
				},
			}
			human := fmt.Sprintf("Login successful for %s", username)
			return output.Write(app.Stdout, app.JSONOutput, human, payload)
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "Account username (email)")
	cmd.Flags().StringVar(&password, "password", "", "Account password (non-interactive; avoid shell history leaks)")
	cmd.Flags().Bool("password-stdin", false, "Read account password from stdin (recommended for complex passwords)")
	return cmd
}

func newAuthStatusCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check whether stored credentials can authenticate",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			creds, err := keyring.LoadCredentials()
			if err != nil {
				payload := map[string]any{"ok": true, "operation": "auth_status", "authenticated": false}
				return output.Write(app.Stdout, app.JSONOutput, "No stored credentials", payload)
			}

			httpClient, err := auth.NewHTTPClient()
			if err != nil {
				return err
			}
			authn := &auth.Authenticator{BaseURL: app.BaseURL(), Client: httpClient}
			if err := authn.Login(ctx, creds.Username, creds.Password); err != nil {
				payload := map[string]any{"ok": true, "operation": "auth_status", "authenticated": false, "reason": err.Error()}
				return output.Write(app.Stdout, app.JSONOutput, "Stored credentials are invalid", payload)
			}

			user, err := authn.CurrentUser(ctx)
			if err != nil {
				payload := map[string]any{"ok": true, "operation": "auth_status", "authenticated": false, "reason": err.Error()}
				return output.Write(app.Stdout, app.JSONOutput, "Stored credentials are invalid", payload)
			}

			payload := map[string]any{
				"ok":            true,
				"operation":     "auth_status",
				"authenticated": true,
				"username":      creds.Username,
				"user": map[string]any{
					"userId":   user["userId"],
					"fullName": user["fullName"],
					"email":    user["email"],
				},
			}
			return output.Write(app.Stdout, app.JSONOutput, "Authenticated", payload)
		},
	}
}

func newAuthLogoutCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete stored credentials from keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := keyring.DeleteCredentials(); err != nil {
				return err
			}
			payload := map[string]any{"ok": true, "operation": "auth_logout"}
			return output.Write(app.Stdout, app.JSONOutput, "Credentials removed", payload)
		},
	}
}

func resolvePassword(app *App, provided string, providedSet bool, fromStdin bool) (string, error) {
	if providedSet && fromStdin {
		return "", fmt.Errorf("use only one of --password or --password-stdin")
	}

	if fromStdin {
		password, err := io.ReadAll(app.Stdin)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		value := strings.TrimRight(string(password), "\r\n")
		if value == "" {
			return "", fmt.Errorf("password is required")
		}
		return value, nil
	}

	if providedSet {
		if provided == "" {
			return "", fmt.Errorf("password is required")
		}
		return provided, nil
	}

	stdinFile, ok := app.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(stdinFile.Fd())) {
		return "", fmt.Errorf("password is required; pass --password or --password-stdin when non-interactive")
	}
	fmt.Fprint(app.Stderr, "Password: ")
	bytes, err := term.ReadPassword(int(stdinFile.Fd()))
	fmt.Fprintln(app.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	password := string(bytes)
	if password == "" {
		return "", fmt.Errorf("password is required")
	}
	return password, nil
}
